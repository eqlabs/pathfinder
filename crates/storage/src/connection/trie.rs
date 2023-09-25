use std::collections::HashMap;

use anyhow::Context;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use pathfinder_common::prelude::*;
use stark_hash::Felt;

use bincode::Options;

use crate::prelude::*;

insert_trie!(insert_class_trie, trie_class, ClassTrieReader);
insert_trie!(insert_contract_trie, trie_contracts, ContractTrieReader);
insert_trie!(insert_storage_trie, trie_storage, StorageTrieReader);

pub(super) fn class_root_index(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<Option<u32>> {
    tx.inner()
        .query_row(
            "SELECT root_index FROM class_roots WHERE block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&block_number],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn storage_root_index(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<Option<u32>> {
    tx.inner()
        .query_row(
            "SELECT root_index FROM storage_roots WHERE block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&block_number],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn contract_root_index(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
) -> anyhow::Result<Option<u32>> {
    tx.inner()
        .query_row(
            "SELECT root_index FROM contract_roots WHERE contract_address = ? AND block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&contract, &block_number],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn contract_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
) -> anyhow::Result<Option<ContractRoot>> {
    tx.inner()
        .query_row(
            r"SELECT hash FROM trie_contracts WHERE idx = (
                SELECT root_index FROM contract_roots WHERE block_number <= ? AND contract_address = ? ORDER BY block_number DESC LIMIT 1
            )",
            params![&block_number, &contract],
            |row| row.get_contract_root(0),
        )
        .optional()
        .map_err(Into::into)
}

pub(super) fn insert_class_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    root: u32,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT INTO class_roots (block_number, root_index) VALUES(?, ?)",
        params![&block_number, &root],
    )?;
    Ok(())
}

pub(super) fn insert_storage_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    root: u32,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT INTO storage_roots (block_number, root_index) VALUES(?, ?)",
        params![&block_number, &root],
    )?;
    Ok(())
}

pub(super) fn insert_contract_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
    root: u32,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT INTO contract_roots (block_number, contract_address, root_index) VALUES(?, ?, ?)",
        params![&block_number, &contract, &root],
    )?;
    Ok(())
}

/// Creates the sql for inserting a node or incrementing its reference count if it already exists, returning
/// the final reference count.
macro_rules! insert_trie {
    ($fn_name: ident, $table: ident, $reader_struct: ident) => {
        /// Stores the node data for this trie in the `$table` table and returns the number of
        /// new nodes that were added i.e. the nodes not already present in the database.
        ///
        /// Inserts nodes starting from the root.
        ///
        /// **NOTE**: since [TrieNode] does not identify leaf nodes explicitly, this function assumes that
        /// any node definition not present in the hash map is in fact a leaf node. This means we recurse through
        /// child nodes until the child node already exists in the database, or the child definition is not present
        /// in the hash map (indicating it is a leaf node, and should not be inserted).
        pub(super) fn $fn_name(
            tx: &rusqlite::Transaction<'_>,
            root: Felt,
            nodes: &HashMap<Felt, Node>,
        ) -> anyhow::Result<u32> {
            let mut stmt = tx
                .prepare_cached(concat!(
                    "INSERT INTO ",
                    stringify!($table),
                    " (hash, data) VALUES(?, ?) RETURNING idx",
                ))
                .context("Creating insert statement")?;

            let mut to_insert = Vec::new();
            let mut to_process = vec![Child::Hash(root)];

            while let Some(node) = to_process.pop() {
                // Only hash variants need to be stored.
                //
                // Leaf nodes never get stored and a node having an
                // ID indicates it has already been stored as part of a
                // previous tree - and its children as well.
                let Child::Hash(hash) = node else {
                    continue;
                };

                let node = nodes.get(&hash).context("New node data is missing")?;

                to_insert.push(hash);

                match node {
                    Node::Binary { left, right } => {
                        to_process.push(left.clone());
                        to_process.push(right.clone());
                    }
                    Node::Edge { child, .. } => {
                        to_process.push(child.clone());
                    }
                    // Leaves are not stored as separate nodes, but the values are serialized in-line.
                    Node::LeafEdge { .. } | Node::LeafBinary { .. } => {}
                }
            }

            let mut indices = HashMap::new();

            // Insert nodes in reverse to ensure children always have an assigned index for the parent to use.
            for hash in to_insert.into_iter().rev() {
                let node = nodes
                    .get(&hash)
                    .expect("Node must exist as hash is dependent on this");

                let data = node.serialize(&indices).context("Serializing node")?;

                let idx: u32 = stmt
                    .query_row(params![&hash.as_be_bytes().as_slice(), &data], |row| {
                        row.get(0)
                    })
                    .context("Inserting node")?;

                indices.insert(hash, idx);
            }

            Ok(*indices
                .get(&root)
                .expect("Root index must exist as we just inserted it"))
        }

        pub struct $reader_struct<'tx>(&'tx Transaction<'tx>);

        impl<'tx> $reader_struct<'tx> {
            pub(super) fn new(tx: &'tx Transaction<'tx>) -> Self {
                Self(tx)
            }

            pub fn get(&self, node: u32) -> anyhow::Result<Option<StoredNode>> {
                // We rely on sqlite caching the statement here. Storing the statement would be nice,
                // however that leads to &mut requirements or interior mutable work-arounds.
                let mut stmt = self
                    .0
                    .inner()
                    .prepare_cached(concat!(
                        "SELECT data FROM ",
                        stringify!($table),
                        " WHERE idx = ?",
                    ))
                    .context("Creating get statement")?;

                let data: Option<Vec<u8>> = stmt
                    .query_row(params![&node], |row| row.get(0))
                    .optional()?;

                let Some(data) = data else {
                    return Ok(None);
                };

                let node = bincode::DefaultOptions::new()
                    .deserialize(&data)
                    .context("Parsing node data")?;

                Ok(Some(node))
            }

            pub fn hash(&self, node: u32) -> anyhow::Result<Option<Felt>> {
                // We rely on sqlite caching the statement here. Storing the statement would be nice,
                // however that leads to &mut requirements or interior mutable work-arounds.
                let mut stmt = self
                    .0
                    .inner()
                    .prepare_cached(concat!(
                        "SELECT hash FROM ",
                        stringify!($table),
                        " WHERE idx = ?",
                    ))
                    .context("Creating get statement")?;

                stmt.query_row(params![&node], |row| row.get_felt(0))
                    .optional()
                    .map_err(Into::into)
            }
        }
    };
}
use insert_trie;

// TODO: optimise path serde. Its wasteful to store the order and offsets etc.
#[derive(Clone, Debug)]
pub enum Node {
    Binary {
        left: Child,
        right: Child,
    },
    Edge {
        child: Child,
        path: BitVec<u8, Msb0>,
    },
    LeafBinary {
        left: Felt,
        right: Felt,
    },
    LeafEdge {
        child: Felt,
        path: BitVec<u8, Msb0>,
    },
}

#[derive(Clone, Debug)]
pub enum Child {
    Id(u32),
    Hash(Felt),
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum StoredNode {
    Binary { left: u32, right: u32 },
    Edge { child: u32, path: BitVec<u8, Msb0> },
    LeafBinary { left: Felt, right: Felt },
    LeafEdge { child: Felt, path: BitVec<u8, Msb0> },
}

impl Node {
    fn serialize(&self, indices: &HashMap<Felt, u32>) -> anyhow::Result<Vec<u8>> {
        let node = match self {
            Node::Binary { left, right } => match (left.clone(), right.clone()) {
                (left, right) => {
                    let left = match left {
                        Child::Id(id) => id,
                        Child::Hash(hash) => *indices.get(&hash).context("Child index missing")?,
                    };

                    let right = match right {
                        Child::Id(id) => id,
                        Child::Hash(hash) => *indices.get(&hash).context("Child index missing")?,
                    };

                    StoredNode::Binary { left, right }
                }
            },
            Node::Edge { child, path } => {
                let child = match child {
                    Child::Id(id) => id,
                    Child::Hash(hash) => indices.get(hash).context("Child index missing")?,
                };

                StoredNode::Edge {
                    child: *child,
                    path: path.clone(),
                }
            }
            Node::LeafEdge { child, path } => StoredNode::LeafEdge {
                child: *child,
                path: path.clone(),
            },
            Node::LeafBinary { left, right } => StoredNode::LeafBinary {
                left: *left,
                right: *right,
            },
        };

        bincode::DefaultOptions::new()
            .serialize(&node)
            .context("Encoding node")
    }
}

#[cfg(test)]
mod tests {
    // use bitvec::prelude::Msb0;
    // use pathfinder_common::felt_bytes;

    // use super::*;

    // #[test]
    // fn trie() {
    //     // Since graph testing and traversal is quite annoying, we use a
    //     // single large test which checks several things at once.
    //     //
    //     // The graph created is unrealistic, but does include two key things:
    //     //  1. edge, binary and leaf node variants
    //     //  2. a node can appear multiple times in the same graph (duplicate)
    //     //
    //     //                       root
    //     //                    /       \
    //     //          left child         right child
    //     //                |               |
    //     //                \              edge
    //     //                 \           /
    //     //                   duplicate
    //     //                  /         \
    //     //            leaf 1           leaf 2

    //     insert_trie!(insert_test, tree_test, TestTrieReader);

    //     let mut db = rusqlite::Connection::open_in_memory().unwrap();
    //     let tx = db.transaction().unwrap();
    //     tx.execute(
    //         "CREATE TABLE tree_test(idx INTEGER PRIMARY KEY, hash BLOB NOT NULL, data BLOB)",
    //         [],
    //     )
    //     .unwrap();

    //     let root_hash = felt_bytes!(b"root node");
    //     let l_child = felt_bytes!(b"left child");
    //     let r_child = felt_bytes!(b"right child");
    //     let edge_hash = felt_bytes!(b"edge node");
    //     let duplicate_hash = felt_bytes!(b"duplicate");
    //     // These must not get inserted.
    //     let leaf_1 = felt_bytes!(b"leaf 1");
    //     let leaf_2 = felt_bytes!(b"leaf 2");

    //     let root_node = TrieNode::Binary {
    //         left: l_child,
    //         right: r_child,
    //     };
    //     let l_node_path = bitvec::bitvec![u8, Msb0; 1, 0, 1, 1, 1];
    //     let l_node = TrieNode::Edge {
    //         child: duplicate_hash,
    //         path: l_node_path.clone(),
    //     };
    //     let r_node_path = bitvec::bitvec![u8, Msb0; 1, 0, 1, 1];
    //     let r_node = TrieNode::Edge {
    //         child: edge_hash,
    //         path: r_node_path.clone(),
    //     };
    //     let edge_node_path = bitvec::bitvec![u8, Msb0; 1, 0, 1, 1, 1, 1, 1];
    //     let edge_node = TrieNode::Edge {
    //         child: duplicate_hash,
    //         path: edge_node_path.clone(),
    //     };
    //     let duplicate_node = TrieNode::Binary {
    //         left: leaf_1,
    //         right: leaf_2,
    //     };

    //     let mut nodes = HashMap::new();
    //     nodes.insert(root_hash, root_node.clone());
    //     nodes.insert(l_child, l_node.clone());
    //     nodes.insert(r_child, r_node.clone());
    //     nodes.insert(edge_hash, edge_node.clone());
    //     nodes.insert(duplicate_hash, duplicate_node.clone());

    //     let iroot = insert_test(&tx, root_hash, &nodes).unwrap();
    //     let db_count: usize = tx
    //         .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
    //         .unwrap();

    //     // We expect inserts for the root, left and right children, edge and 2x duplicate node.
    //     assert_eq!(db_count, 6);

    //     // Inserting the same trie again should double every node.
    //     let iroot2 = insert_test(&tx, root_hash, &nodes).unwrap();
    //     let db_count: usize = tx
    //         .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
    //         .unwrap();
    //     assert_eq!(db_count, 12);
    //     assert_ne!(iroot, iroot2);

    //     let tx = Transaction::from_inner(tx);

    //     let reader = TestTrieReader::new(&tx);

    //     // Ensure the root node is correct.
    //     let root = reader.get(iroot).unwrap().unwrap();
    //     assert_eq!(root.hash, root_hash);
    //     let Node::Binary { left, right } = root.variant else {
    //         panic!("Root was not a binary node");
    //     };

    //     // l_node
    //     let left = reader.get(left).unwrap().unwrap();
    //     assert_eq!(left.hash, l_child);
    //     let Node::Edge { child, path } = left.variant else {
    //         panic!("l_node was not an edge node");
    //     };
    //     assert_eq!(path, l_node_path);
    //     let iduplicate = child;

    //     // r_node
    //     let right = reader.get(right).unwrap().unwrap();
    //     assert_eq!(right.hash, r_child);
    //     let Node::Edge { child, path } = right.variant else {
    //         panic!("r_node was not an edge node");
    //     };
    //     assert_eq!(path, r_node_path);
    //     let iedge = child;

    //     // duplicate
    //     let duplicate = reader.get(iduplicate).unwrap().unwrap();
    //     assert_eq!(duplicate.hash, duplicate_hash);
    //     let Node::BinaryLeaf { left, right } = duplicate.variant else {
    //         panic!("Root was not a binary node");
    //     };
    //     assert_eq!(left, leaf_1);
    //     assert_eq!(right, leaf_2);

    //     // edge_node (points to a different duplicate)
    //     let edge = reader.get(iedge).unwrap().unwrap();
    //     assert_eq!(edge.hash, edge_hash);
    //     let Node::Edge { child, path } = edge.variant else {
    //         panic!("r_node was not an edge node");
    //     };
    //     assert_eq!(path, edge_node_path);
    //     let iduplicate2 = child;

    //     // duplicate 2
    //     let duplicate = reader.get(iduplicate2).unwrap().unwrap();
    //     assert_eq!(duplicate.hash, duplicate_hash);
    //     let Node::BinaryLeaf { left, right } = duplicate.variant else {
    //         panic!("Root was not a binary node");
    //     };
    //     assert_eq!(left, leaf_1);
    //     assert_eq!(right, leaf_2);
    // }
}
