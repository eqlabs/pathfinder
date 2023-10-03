use std::collections::HashMap;

use anyhow::Context;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use pathfinder_common::prelude::*;
use stark_hash::Felt;

use crate::prelude::*;

macros::create_trie_fns!(trie_class);
macros::create_trie_fns!(trie_contracts);
macros::create_trie_fns!(trie_storage);

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

pub(super) fn insert_contract_state_hash(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
    state_hash: ContractStateHash,
) -> anyhow::Result<()> {
    tx.inner().execute("INSERT INTO contract_state_hashes(block_number, contract_address, state_hash) VALUES(?,?,?)", 
        params![&block_number, &contract, &state_hash])?;

    Ok(())
}

pub(super) fn contract_state_hash(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
) -> anyhow::Result<Option<ContractStateHash>> {
    tx.inner()
        .query_row(
            "SELECT state_hash FROM contract_state_hashes WHERE contract_address = ? AND block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&contract, &block_number],
            |row| row.get_contract_state_hash(0),
        )
        .optional()
        .map_err(Into::into)
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

mod macros {
    /// Generates the `insert`, `node` and `hash` trie functions for the given table name, within
    /// a module with the table name.
    macro_rules! create_trie_fns {
        ($table: ident) => {
            pub(super) mod $table {
                use super::*;

                /// Stores the node data for this trie and returns the index of the root.
                pub fn insert(
                    tx: &Transaction<'_>,
                    root: Felt,
                    nodes: &HashMap<Felt, Node>,
                ) -> anyhow::Result<u32> {
                    let mut stmt = tx
                        .inner()
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
                            // Leaves are not stored as separate nodes but are instead serialized in-line in their parents.
                            Node::LeafEdge { .. } | Node::LeafBinary { .. } => {}
                        }
                    }

                    let mut indices = HashMap::new();

                    // Reusable (and oversized) buffer for encoding.
                    let mut buffer = vec![0u8; 256];

                    // Insert nodes in reverse to ensure children always have an assigned index for the parent to use.
                    for hash in to_insert.into_iter().rev() {
                        let node = nodes
                            .get(&hash)
                            .expect("Node must exist as hash is dependent on this");

                        let node = node.into_stored(&indices)?;

                        let length = node.encode(&mut buffer).context("Encoding node")?;

                        let idx: u32 = stmt
                            .query_row(
                                params![&hash.as_be_bytes().as_slice(), &&buffer[..length]],
                                |row| row.get(0),
                            )
                            .context("Inserting node")?;

                        indices.insert(hash, idx);
                    }

                    Ok(*indices
                        .get(&root)
                        .expect("Root index must exist as we just inserted it"))
                }

                /// Returns the node with the given index.
                pub fn node(
                    tx: &Transaction<'_>,
                    index: u32,
                ) -> anyhow::Result<Option<StoredNode>> {
                    // We rely on sqlite caching the statement here. Storing the statement would be nice,
                    // however that leads to &mut requirements or interior mutable work-arounds.
                    let mut stmt = tx
                        .inner()
                        .prepare_cached(concat!(
                            "SELECT data FROM ",
                            stringify!($table),
                            " WHERE idx = ?",
                        ))
                        .context("Creating get statement")?;

                    let Some(data): Option<Vec<u8>> = stmt
                        .query_row(params![&index], |row| row.get(0))
                        .optional()?
                    else {
                        return Ok(None);
                    };

                    let node = StoredNode::decode(&data).context("Decoding node")?;

                    Ok(Some(node))
                }

                /// Returns the hash of the node with the given index.
                pub fn hash(tx: &Transaction<'_>, index: u32) -> anyhow::Result<Option<Felt>> {
                    // We rely on sqlite caching the statement here. Storing the statement would be nice,
                    // however that leads to &mut requirements or interior mutable work-arounds.
                    let mut stmt = tx
                        .inner()
                        .prepare_cached(concat!(
                            "SELECT hash FROM ",
                            stringify!($table),
                            " WHERE idx = ?",
                        ))
                        .context("Creating get statement")?;

                    stmt.query_row(params![&index], |row| row.get_felt(0))
                        .optional()
                        .map_err(Into::into)
                }
            }
        };
    }

    pub(super) use create_trie_fns;
}

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
    LeafBinary,
    LeafEdge {
        path: BitVec<u8, Msb0>,
    },
}

#[derive(Clone, Debug)]
pub enum Child {
    Id(u32),
    Hash(Felt),
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u32, right: u32 },
    Edge { child: u32, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Clone, Debug, bincode::Encode, bincode::BorrowDecode)]
enum StoredSerde {
    Binary { left: u32, right: u32 },
    Edge { child: u32, path: Vec<u8> },
    LeafBinary,
    LeafEdge { path: Vec<u8> },
}

impl StoredNode {
    const CODEC_CFG: bincode::config::Configuration = bincode::config::standard();

    /// Writes the [StoredNode] into `buffer` and returns the number of bytes written.
    fn encode(&self, mut buffer: &mut [u8]) -> Result<usize, bincode::error::EncodeError> {
        let helper = match self {
            Self::Binary { left, right } => StoredSerde::Binary {
                left: *left,
                right: *right,
            },
            Self::Edge { child, path } => {
                let path_length = path.len() as u8;

                let mut path = path.to_owned();
                path.force_align();
                let mut path = path.into_vec();
                path.push(path_length);

                StoredSerde::Edge {
                    child: *child,
                    path,
                }
            }
            Self::LeafBinary => StoredSerde::LeafBinary,
            Self::LeafEdge { path } => {
                let path_length = path.len() as u8;

                let mut path = path.to_owned();
                path.force_align();
                let mut path = path.into_vec();
                path.push(path_length);

                StoredSerde::LeafEdge { path }
            }
        };
        // Do not use serialize() as this will invoke serialization twice.
        // https://github.com/bincode-org/bincode/issues/401
        bincode::encode_into_slice(&helper, &mut buffer, Self::CODEC_CFG)
    }

    fn decode(data: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        let helper = bincode::borrow_decode_from_slice(data, Self::CODEC_CFG)?;

        let node = match helper.0 {
            StoredSerde::Binary { left, right } => Self::Binary { left, right },
            StoredSerde::Edge { child, mut path } => {
                let path_length = path.pop().ok_or(bincode::error::DecodeError::Other(
                    "Edge node's path length is missing",
                ))?;
                let mut path = bitvec::vec::BitVec::from_vec(path);
                path.resize(path_length as usize, false);
                Self::Edge { child, path }
            }
            StoredSerde::LeafBinary => Self::LeafBinary,
            StoredSerde::LeafEdge { mut path } => {
                let path_length = path.pop().ok_or(bincode::error::DecodeError::Other(
                    "Edge node's path length is missing",
                ))?;
                let mut path = bitvec::vec::BitVec::from_vec(path);
                path.resize(path_length as usize, false);
                Self::LeafEdge { path }
            }
        };

        Ok(node)
    }
}

#[cfg(test)]
impl StoredNode {
    fn as_binary(self) -> Option<(u32, u32)> {
        match self {
            Self::Binary { left, right } => Some((left, right)),
            _ => None,
        }
    }

    fn as_edge(self) -> Option<(u32, BitVec<u8, Msb0>)> {
        match self {
            Self::Edge { child, path } => Some((child, path)),
            _ => None,
        }
    }

    fn as_binary_leaf(self) -> Option<()> {
        match self {
            Self::LeafBinary => Some(()),
            _ => None,
        }
    }

    fn as_edge_leaf(self) -> Option<BitVec<u8, Msb0>> {
        match self {
            Self::LeafEdge { path } => Some(path),
            _ => None,
        }
    }
}

impl Node {
    fn into_stored(&self, indices: &HashMap<Felt, u32>) -> anyhow::Result<StoredNode> {
        let node = match self {
            Node::Binary { left, right } => match (left.clone(), right.clone()) {
                (left, right) => {
                    let left = match left {
                        Child::Id(id) => id,
                        Child::Hash(hash) => {
                            *indices.get(&hash).context("Left child index missing")?
                        }
                    };

                    let right = match right {
                        Child::Id(id) => id,
                        Child::Hash(hash) => {
                            *indices.get(&hash).context("Right child index missing")?
                        }
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
            Node::LeafEdge { path } => StoredNode::LeafEdge { path: path.clone() },
            Node::LeafBinary => StoredNode::LeafBinary,
        };

        Ok(node)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;

    #[test]
    fn class_roots() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let result = class_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, None);

        insert_class_root(&tx, BlockNumber::GENESIS, 123).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));

        insert_class_root(&tx, BlockNumber::GENESIS + 1, 456).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 1).unwrap();
        assert_eq!(result, Some(456));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 2).unwrap();
        assert_eq!(result, Some(456));

        insert_class_root(&tx, BlockNumber::GENESIS + 10, 789).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS + 9).unwrap();
        assert_eq!(result, Some(456));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 10).unwrap();
        assert_eq!(result, Some(789));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 11).unwrap();
        assert_eq!(result, Some(789));
    }

    #[test]
    fn storage_roots() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let result = storage_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, None);

        insert_storage_root(&tx, BlockNumber::GENESIS, 123).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));

        insert_storage_root(&tx, BlockNumber::GENESIS + 1, 456).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 1).unwrap();
        assert_eq!(result, Some(456));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 2).unwrap();
        assert_eq!(result, Some(456));

        insert_storage_root(&tx, BlockNumber::GENESIS + 10, 789).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 9).unwrap();
        assert_eq!(result, Some(456));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 10).unwrap();
        assert_eq!(result, Some(789));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 11).unwrap();
        assert_eq!(result, Some(789));
    }

    #[test]
    fn contract_roots() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let c1 = contract_address_bytes!(b"first");
        let c2 = contract_address_bytes!(b"second");

        // Simplest trie node setup so we can test the fetching of contract root hashes.
        let root0 = contract_root_bytes!(b"root 0");
        let root_node = Node::LeafBinary;
        let mut nodes = HashMap::new();
        nodes.insert(root0.0, root_node.clone());

        let idx0 = trie_contracts::insert(&tx, root0.0, &nodes).unwrap();

        let result1 = contract_root_index(&tx, BlockNumber::GENESIS, c1).unwrap();
        assert_eq!(result1, None);

        insert_contract_root(&tx, BlockNumber::GENESIS, c1, idx0).unwrap();
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS, c1).unwrap();
        let hash2 = contract_root(&tx, BlockNumber::GENESIS, c2).unwrap();
        assert_eq!(result1, Some(idx0));
        assert_eq!(result2, None);
        assert_eq!(hash1, Some(root0));
        assert_eq!(hash2, None);

        let root1 = contract_root_bytes!(b"root 1");
        nodes.clear();
        nodes.insert(root1.0, root_node.clone());
        let idx1 = trie_contracts::insert(&tx, root1.0, &nodes).unwrap();

        insert_contract_root(&tx, BlockNumber::GENESIS + 1, c1, idx1).unwrap();
        insert_contract_root(&tx, BlockNumber::GENESIS + 1, c2, 888).unwrap();
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS, c1).unwrap();
        assert_eq!(result1, Some(idx0));
        assert_eq!(result2, None);
        assert_eq!(hash1, Some(root0));
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS + 1, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS + 1, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 1, c1).unwrap();
        assert_eq!(result1, Some(idx1));
        assert_eq!(result2, Some(888));
        assert_eq!(hash1, Some(root1));
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS + 2, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS + 2, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 2, c1).unwrap();
        assert_eq!(result1, Some(idx1));
        assert_eq!(result2, Some(888));
        assert_eq!(hash1, Some(root1));

        let root2 = contract_root_bytes!(b"root 2");
        nodes.clear();
        nodes.insert(root2.0, root_node.clone());
        let idx2 = trie_contracts::insert(&tx, root2.0, &nodes).unwrap();

        insert_contract_root(&tx, BlockNumber::GENESIS + 10, c1, idx2).unwrap();
        insert_contract_root(&tx, BlockNumber::GENESIS + 11, c2, 999).unwrap();
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS + 9, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS + 9, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 9, c1).unwrap();
        assert_eq!(result1, Some(idx1));
        assert_eq!(result2, Some(888));
        assert_eq!(hash1, Some(root1));
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS + 10, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS + 10, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 10, c1).unwrap();
        assert_eq!(result1, Some(idx2));
        assert_eq!(result2, Some(888));
        assert_eq!(hash1, Some(root2));
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS + 11, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 11, c1).unwrap();
        assert_eq!(result2, Some(999));
        assert_eq!(hash1, Some(root2));
    }

    #[rstest::rstest]
    #[case::binary(StoredNode::Binary {
        left: 12, right: 34
    })]
    #[case::edge(StoredNode::Edge {
        child: 123,
        path: bitvec::bitvec![u8, Msb0; 1,0,0,1,0,1,0,0,0,0,0,1,1,1,1]
    })]
    #[case::binary(StoredNode::LeafBinary)]
    #[case::binary(StoredNode::LeafEdge {
        path: bitvec::bitvec![u8, Msb0; 1,0,0,1,0,1,0,0,0,0,0,1,1,1,1]
    })]
    #[case::edge_max_path(StoredNode::Edge {
        child: 123,
        path: bitvec::bitvec![u8, Msb0; 1; 251]
    })]
    #[case::edge_min_path(StoredNode::Edge {
        child: 123,
        path: bitvec::bitvec![u8, Msb0; 0]
    })]
    fn serde(#[case] node: StoredNode) {
        let mut buffer = vec![0; 256];
        let length = node.encode(&mut buffer).unwrap();
        let result = StoredNode::decode(&buffer[..length]).unwrap();

        assert_eq!(result, node);
    }

    mod trie_fns {
        use super::*;
        macros::create_trie_fns!(test_table);

        fn setup_db() -> rusqlite::Connection {
            let db = rusqlite::Connection::open_in_memory().unwrap();
            db.execute(
                "CREATE TABLE test_table (idx INTEGER PRIMARY KEY,hash BLOB NOT NULL,data BLOB) ",
                [],
            )
            .unwrap();

            db
        }

        mod missing_child_is_error {
            use super::*;

            #[test]
            fn root() {
                let mut db = setup_db();
                let tx = db.transaction().unwrap();
                let tx = crate::Transaction::from_inner(tx);

                test_table::insert(&tx, felt_bytes!(b"missing"), &HashMap::new()).unwrap_err();
            }

            #[test]
            fn binary() {
                let mut db = setup_db();
                let tx = db.transaction().unwrap();
                let tx = crate::Transaction::from_inner(tx);

                let root = felt_bytes!(b"root");
                let mut nodes = HashMap::new();
                nodes.insert(
                    root,
                    Node::Binary {
                        left: Child::Hash(felt_bytes!(b"missing")),
                        right: Child::Hash(felt_bytes!(b"exists")),
                    },
                );
                nodes.insert(
                    felt_bytes!(b"exists"),
                    Node::Edge {
                        child: Child::Hash(felt_bytes!(b"leaf")),
                        path: bitvec::bitvec![u8, Msb0; 251; 1],
                    },
                );

                test_table::insert(&tx, root, &nodes).unwrap_err();
            }

            #[test]
            fn edge() {
                let mut db = setup_db();
                let tx = db.transaction().unwrap();
                let tx = crate::Transaction::from_inner(tx);

                let root = felt_bytes!(b"root");
                let mut nodes = HashMap::new();
                nodes.insert(
                    root,
                    Node::Edge {
                        child: Child::Hash(felt_bytes!(b"missing")),
                        path: bitvec::bitvec![u8, Msb0; 251; 1],
                    },
                );

                test_table::insert(&tx, root, &nodes).unwrap_err();
            }
        }

        #[test]
        fn one_of_each_node() {
            // Create an (unrealistic) tree containing each of the node types and ensure
            // the tree and its hashes are retrieved accurately.
            let mut db = setup_db();
            let tx = db.transaction().unwrap();
            let tx = crate::Transaction::from_inner(tx);

            let edge_leaf_hash = felt_bytes!(b"edge leaf");
            let edge_leaf_node = Node::LeafEdge {
                path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1],
            };

            let binary_leaf_hash = felt_bytes!(b"binary leaf");
            let binary_leaf_node = Node::LeafBinary;

            let edge_hash = felt_bytes!(b"edge");
            let edge_node = Node::Edge {
                child: Child::Hash(binary_leaf_hash),
                path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1],
            };

            let root_hash = felt_bytes!(b"root");
            let root_node = Node::Binary {
                left: Child::Hash(edge_hash),
                right: Child::Hash(edge_leaf_hash),
            };

            let mut nodes = HashMap::new();
            nodes.insert(edge_leaf_hash, edge_leaf_node);
            nodes.insert(binary_leaf_hash, binary_leaf_node);
            nodes.insert(edge_hash, edge_node);
            nodes.insert(root_hash, root_node);

            let root_idx = test_table::insert(&tx, root_hash, &nodes).unwrap();

            // Root node
            let hash = test_table::hash(&tx, root_idx).unwrap();
            assert_eq!(hash, Some(root_hash));
            let node = test_table::node(&tx, root_idx).unwrap().unwrap();
            let (left, right) = node.as_binary().unwrap();

            // Right child is the edge leaf
            let hash = test_table::hash(&tx, right).unwrap();
            assert_eq!(hash, Some(edge_leaf_hash));
            let node = test_table::node(&tx, right).unwrap().unwrap();
            let path = node.as_edge_leaf().unwrap();
            assert_eq!(path, bitvec::bitvec![u8, Msb0; 1,0,1,1,1]);

            // Left child is the edge node
            let hash = test_table::hash(&tx, left).unwrap();
            assert_eq!(hash, Some(edge_hash));
            let node = test_table::node(&tx, left).unwrap().unwrap();
            let (child, path) = node.as_edge().unwrap();
            assert_eq!(path, bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1]);

            // Edge's child is the binary leaf
            let hash = test_table::hash(&tx, child).unwrap();
            assert_eq!(hash, Some(binary_leaf_hash));
            let node = test_table::node(&tx, child).unwrap().unwrap();
            node.as_binary_leaf().unwrap();
        }

        #[test]
        fn index_children() {
            // Insert nodes which use indices as children instead of hashes.
            // The indices don't actually need to point to real nodes since this
            // isn't enforced within the db.
            let mut db = setup_db();
            let tx = db.transaction().unwrap();
            let tx = crate::Transaction::from_inner(tx);

            let edge_hash = felt_bytes!(b"edge");
            let edge_node = Node::Edge {
                child: Child::Id(123),
                path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1],
            };

            let binary_hash0 = felt_bytes!(b"binary");
            let binary_node0 = Node::Binary {
                left: Child::Id(456),
                right: Child::Id(777),
            };

            let root_hash = felt_bytes!(b"root");
            let root_node = Node::Binary {
                left: Child::Hash(edge_hash),
                right: Child::Hash(binary_hash0),
            };

            let mut nodes = HashMap::new();
            nodes.insert(edge_hash, edge_node);
            nodes.insert(binary_hash0, binary_node0);
            nodes.insert(root_hash, root_node);

            let root_idx = test_table::insert(&tx, root_hash, &nodes).unwrap();

            // Root node
            let hash = test_table::hash(&tx, root_idx).unwrap();
            assert_eq!(hash, Some(root_hash));
            let node = test_table::node(&tx, root_idx).unwrap().unwrap();
            let (left, right) = node.as_binary().unwrap();

            // Right child is the binary node
            let hash = test_table::hash(&tx, right).unwrap();
            assert_eq!(hash, Some(binary_hash0));
            let node = test_table::node(&tx, right).unwrap().unwrap();
            let children = node.as_binary().unwrap();
            assert_eq!(children, (456, 777));

            // Left child is the edge node
            let hash = test_table::hash(&tx, left).unwrap();
            assert_eq!(hash, Some(edge_hash));
            let node = test_table::node(&tx, left).unwrap().unwrap();
            let (child, path) = node.as_edge().unwrap();
            assert_eq!(path, bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1]);
            assert_eq!(child, 123);
        }
    }

    #[test]
    fn contract_state_hash() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let contract = contract_address_bytes!(b"address");
        let state_hash = contract_state_hash_bytes!(b"state hash");

        insert_contract_state_hash(&tx, BlockNumber::GENESIS + 2, contract, state_hash).unwrap();

        let result = super::contract_state_hash(&tx, BlockNumber::GENESIS, contract).unwrap();
        assert!(result.is_none());

        let result = super::contract_state_hash(&tx, BlockNumber::GENESIS + 2, contract).unwrap();
        assert_eq!(result, Some(state_hash));

        let result = super::contract_state_hash(&tx, BlockNumber::GENESIS + 10, contract).unwrap();
        assert_eq!(result, Some(state_hash));

        let result = super::contract_state_hash(
            &tx,
            BlockNumber::GENESIS + 2,
            contract_address_bytes!(b"missing"),
        )
        .unwrap();
        assert!(result.is_none());
    }
}
