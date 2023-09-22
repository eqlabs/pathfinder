use std::collections::HashMap;

use anyhow::Context;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use pathfinder_common::trie::TrieNode;
use stark_hash::Felt;

use bincode::Options;

use crate::prelude::*;

insert_trie!(insert_class_trie, trir_class, ClassTrieReader);
insert_trie!(insert_contract_trie, trie_contracts, ContractTrieReader);
insert_trie!(insert_storage_trie, trie_storage, StorageTrieReader);

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
            nodes: &HashMap<Felt, TrieNode>,
        ) -> anyhow::Result<u32> {
            if root.is_zero() {
                // TODO: what should actually happen here?
                return Ok(u32::MAX);
            }

            let mut stmt = tx
                .prepare_cached(concat!(
                    "INSERT INTO ",
                    stringify!($table),
                    " (hash, data) VALUES(?, ?) RETURNING idx",
                ))
                .context("Creating insert statement")?;

            let mut to_insert = Vec::new();
            let mut to_process = vec![root];

            while let Some(hash) = to_process.pop() {
                let Some(node) = nodes.get(&hash) else {
                    continue;
                };

                to_insert.push(hash);

                match node {
                    TrieNode::Binary { left, right } => {
                        to_process.push(*left);
                        to_process.push(*right);
                    }
                    TrieNode::Edge { child, .. } => {
                        to_process.push(*child);
                    }
                }
            }

            let mut indices = HashMap::new();

            // Insert nodes in reverse to ensure children always have an assigned index for the parent to use.
            for hash in to_insert.into_iter().rev() {
                let node = nodes
                    .get(&hash)
                    .expect("Node must exist as hash is dependent on this");

                let variant = match node {
                    TrieNode::Binary { left, right } => {
                        let ileft = indices.get(left);
                        let iright = indices.get(right);

                        match (ileft, iright) {
                            (Some(left), Some(right)) => StoredNodeVariant::Binary {
                                left: *left as u32,
                                right: *right as u32,
                            },
                            (None, None) => StoredNodeVariant::BinaryLeaf {
                                left: *left,
                                right: *right,
                            },
                            mismatch => {
                                panic!("Both children should be some or none: {mismatch:?}")
                            }
                        }
                    }
                    TrieNode::Edge { child, path } => match indices.get(child) {
                        Some(child) => StoredNodeVariant::Edge {
                            child: *child as u32,
                            path: path.clone(),
                        },
                        None => StoredNodeVariant::EdgeLeaf {
                            child: *child,
                            path: path.clone(),
                        },
                    },
                };

                let data = bincode::DefaultOptions::new()
                    .serialize(&variant)
                    .context("Serializing node data")?;

                let idx: u32 = stmt
                    .query_row(params![&hash.as_be_bytes().as_slice(), &data], |row| {
                        row.get(0)
                    })
                    .context("Inserting node")?;

                indices.insert(hash, idx);
            }

            dbg!(&indices);
            dbg!(root);

            Ok(*indices
                .get(&root)
                .expect("Root index must exist as we just inserted it"))
        }

        pub struct $reader_struct<'tx>(&'tx Transaction<'tx>);

        impl<'tx> $reader_struct<'tx> {
            pub(super) fn new(tx: &'tx Transaction<'tx>) -> Self {
                Self(tx)
            }

            pub fn get_root(&self, hash: stark_hash::Felt) -> anyhow::Result<Option<u32>> {
                let mut stmt = self
                    .0
                    .inner()
                    .prepare_cached(concat!(
                        "SELECT idx FROM ",
                        stringify!($table),
                        " WHERE hash = ?",
                    ))
                    .context("Creating get statement")?;

                let index: Option<u32> = stmt
                    .query_row(params![&hash.as_be_bytes().as_slice()], |row| row.get(0))
                    .optional()?;

                Ok(index)
            }

            pub fn get(&self, node: u32) -> anyhow::Result<Option<StoredNode>> {
                // We rely on sqlite caching the statement here. Storing the statement would be nice,
                // however that leads to &mut requirements or interior mutable work-arounds.
                let mut stmt = self
                    .0
                    .inner()
                    .prepare_cached(concat!(
                        "SELECT data, hash FROM ",
                        stringify!($table),
                        " WHERE idx = ?",
                    ))
                    .context("Creating get statement")?;

                let node: Option<(Vec<u8>, Felt)> = stmt
                    .query_row(params![&node], |row| {
                        let data = row.get(0)?;
                        let hash = row.get_felt(1)?;

                        Ok((data, hash))
                    })
                    .optional()?;

                let Some((variant, hash)) = node else {
                    return Ok(None);
                };

                let variant: StoredNodeVariant = bincode::DefaultOptions::new()
                    .deserialize(&variant)
                    .context("Parsing node data")?;

                let node = StoredNode { variant, hash };

                Ok(Some(node))
            }
        }
    };
}
use insert_trie;

#[derive(Clone, Debug)]
pub struct StoredNode {
    pub hash: Felt,
    pub variant: StoredNodeVariant,
}

// TODO: optimise path serde. Its wasteful to store the order and offsets etc.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum StoredNodeVariant {
    Binary { left: u32, right: u32 },
    Edge { child: u32, path: BitVec<u8, Msb0> },
    BinaryLeaf { left: Felt, right: Felt },
    EdgeLeaf { child: Felt, path: BitVec<u8, Msb0> },
}

#[cfg(test)]
mod tests {
    use bitvec::prelude::Msb0;
    use pathfinder_common::felt_bytes;

    use super::*;

    #[test]
    fn trie() {
        // Since graph testing and traversal is quite annoying, we use a
        // single large test which checks several things at once.
        //
        // The graph created is unrealistic, but does include two key things:
        //  1. edge, binary and leaf node variants
        //  2. a node can appear multiple times in the same graph (duplicate)
        //
        //                       root
        //                    /       \
        //          left child         right child
        //                |               |
        //                \              edge
        //                 \           /
        //                   duplicate
        //                  /         \
        //            leaf 1           leaf 2

        insert_trie!(insert_test, tree_test, TestTrieReader);

        let mut db = rusqlite::Connection::open_in_memory().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "CREATE TABLE tree_test(idx INTEGER PRIMARY KEY, hash BLOB NOT NULL, data BLOB)",
            [],
        )
        .unwrap();

        let root_hash = felt_bytes!(b"root node");
        let l_child = felt_bytes!(b"left child");
        let r_child = felt_bytes!(b"right child");
        let edge_hash = felt_bytes!(b"edge node");
        let duplicate_hash = felt_bytes!(b"duplicate");
        // These must not get inserted.
        let leaf_1 = felt_bytes!(b"leaf 1");
        let leaf_2 = felt_bytes!(b"leaf 2");

        let root_node = TrieNode::Binary {
            left: l_child,
            right: r_child,
        };
        let l_node_path = bitvec::bitvec![u8, Msb0; 1, 0, 1, 1, 1];
        let l_node = TrieNode::Edge {
            child: duplicate_hash,
            path: l_node_path.clone(),
        };
        let r_node_path = bitvec::bitvec![u8, Msb0; 1, 0, 1, 1];
        let r_node = TrieNode::Edge {
            child: edge_hash,
            path: r_node_path.clone(),
        };
        let edge_node_path = bitvec::bitvec![u8, Msb0; 1, 0, 1, 1, 1, 1, 1];
        let edge_node = TrieNode::Edge {
            child: duplicate_hash,
            path: edge_node_path.clone(),
        };
        let duplicate_node = TrieNode::Binary {
            left: leaf_1,
            right: leaf_2,
        };

        let mut nodes = HashMap::new();
        nodes.insert(root_hash, root_node.clone());
        nodes.insert(l_child, l_node.clone());
        nodes.insert(r_child, r_node.clone());
        nodes.insert(edge_hash, edge_node.clone());
        nodes.insert(duplicate_hash, duplicate_node.clone());

        let iroot = insert_test(&tx, root_hash, &nodes).unwrap();
        let db_count: usize = tx
            .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
            .unwrap();

        // We expect inserts for the root, left and right children, edge and 2x duplicate node.
        assert_eq!(db_count, 6);

        // Inserting the same trie again should double every node.
        let iroot2 = insert_test(&tx, root_hash, &nodes).unwrap();
        let db_count: usize = tx
            .query_row("SELECT COUNT(1) FROM tree_test", [], |row| row.get(0))
            .unwrap();
        assert_eq!(db_count, 12);
        assert_ne!(iroot, iroot2);

        let tx = Transaction::from_inner(tx);

        let reader = TestTrieReader::new(&tx);

        // Ensure the root node is correct.
        let root = reader.get(iroot).unwrap().unwrap();
        assert_eq!(root.hash, root_hash);
        let StoredNodeVariant::Binary { left, right } = root.variant else {
            panic!("Root was not a binary node");
        };

        // l_node
        let left = reader.get(left).unwrap().unwrap();
        assert_eq!(left.hash, l_child);
        let StoredNodeVariant::Edge { child, path } = left.variant else {
            panic!("l_node was not an edge node");
        };
        assert_eq!(path, l_node_path);
        let iduplicate = child;

        // r_node
        let right = reader.get(right).unwrap().unwrap();
        assert_eq!(right.hash, r_child);
        let StoredNodeVariant::Edge { child, path } = right.variant else {
            panic!("r_node was not an edge node");
        };
        assert_eq!(path, r_node_path);
        let iedge = child;

        // duplicate
        let duplicate = reader.get(iduplicate).unwrap().unwrap();
        assert_eq!(duplicate.hash, duplicate_hash);
        let StoredNodeVariant::BinaryLeaf { left, right } = duplicate.variant else {
            panic!("Root was not a binary node");
        };
        assert_eq!(left, leaf_1);
        assert_eq!(right, leaf_2);

        // edge_node (points to a different duplicate)
        let edge = reader.get(iedge).unwrap().unwrap();
        assert_eq!(edge.hash, edge_hash);
        let StoredNodeVariant::Edge { child, path } = edge.variant else {
            panic!("r_node was not an edge node");
        };
        assert_eq!(path, edge_node_path);
        let iduplicate2 = child;

        // duplicate 2
        let duplicate = reader.get(iduplicate2).unwrap().unwrap();
        assert_eq!(duplicate.hash, duplicate_hash);
        let StoredNodeVariant::BinaryLeaf { left, right } = duplicate.variant else {
            panic!("Root was not a binary node");
        };
        assert_eq!(left, leaf_1);
        assert_eq!(right, leaf_2);
    }
}
