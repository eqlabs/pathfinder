use std::collections::HashMap;

use anyhow::Context;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use pathfinder_common::prelude::*;
use pathfinder_crypto::Felt;

use crate::prelude::*;

macros::create_trie_fns!(trie_class);
macros::create_trie_fns!(trie_contracts);
macros::create_trie_fns!(trie_storage);

pub(super) fn class_root_index(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<Option<u64>> {
    tx.inner()
        .query_row(
            "SELECT root_index FROM class_roots WHERE block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&block_number],
            |row| row.get::<_, Option<u64>>(0),
        )
        .optional()
        .map(|x| x.flatten())
        .map_err(Into::into)
}

pub(super) fn class_root_exists(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<bool> {
    tx.inner()
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM class_roots WHERE block_number=?)",
            params![&block_number],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

pub(super) fn storage_root_index(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<Option<u64>> {
    tx.inner()
        .query_row(
            "SELECT root_index FROM storage_roots WHERE block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&block_number],
            |row| row.get::<_, Option<u64>>(0),
        )
        .optional()
        .map(|x| x.flatten())
        .map_err(Into::into)
}

pub(super) fn storage_root_exists(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
) -> anyhow::Result<bool> {
    tx.inner()
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM storage_roots WHERE block_number=?)",
            params![&block_number],
            |row| row.get::<_, bool>(0),
        )
        .map_err(Into::into)
}

pub(super) fn contract_root_index(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
) -> anyhow::Result<Option<u64>> {
    tx.inner()
        .query_row(
            "SELECT root_index FROM contract_roots WHERE contract_address = ? AND block_number <= ? ORDER BY block_number DESC LIMIT 1",
            params![&contract, &block_number],
            |row| row.get::<_, Option<u64>>(0),
        )
        .optional()
        .map(|x| x.flatten())
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
    root: Option<u64>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT INTO class_roots (block_number, root_index) VALUES(?, ?)",
        params![&block_number, &root],
    )?;
    Ok(())
}

pub(super) fn insert_or_update_class_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    root: Option<u64>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT OR REPLACE INTO class_roots (block_number, root_index) VALUES(?, ?)",
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
    root: Option<u64>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT INTO storage_roots (block_number, root_index) VALUES(?, ?)",
        params![&block_number, &root],
    )?;
    Ok(())
}

pub(super) fn insert_or_update_storage_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    root: Option<u64>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT OR REPLACE INTO storage_roots (block_number, root_index) VALUES(?, ?)",
        params![&block_number, &root],
    )?;
    Ok(())
}

pub(super) fn insert_contract_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
    root: Option<u64>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT INTO contract_roots (block_number, contract_address, root_index) VALUES(?, ?, ?)",
        params![&block_number, &contract, &root],
    )?;
    Ok(())
}

pub(super) fn insert_or_update_contract_root(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    contract: ContractAddress,
    root: Option<u64>,
) -> anyhow::Result<()> {
    tx.inner().execute(
        "INSERT OR REPLACE INTO contract_roots (block_number, contract_address, root_index) VALUES(?, ?, ?)",
        params![&block_number, &contract, &root],
    )?;
    Ok(())
}

const METRIC_TRIE_NODES_REMOVED: &str = "pathfinder_storage_trie_nodes_deleted_total";
const METRIC_TRIE_NODES_ADDED: &str = "pathfinder_storage_trie_nodes_added_total";

mod macros {
    /// Generates the `insert`, `node` and `hash` trie functions for the given table name, within
    /// a module with the table name.
    macro_rules! create_trie_fns {
        ($table: ident) => {
            pub(super) mod $table {
                use super::*;

                pub fn remove(tx: &Transaction<'_>, removed: &[u64]) -> anyhow::Result<()> {
                    let mut stmt = tx
                        .inner()
                        .prepare_cached(concat!(
                            "DELETE FROM ",
                            stringify!($table),
                            " WHERE idx = ?",
                        ))
                        .context("Creating delete statement")?;

                    let number_of_nodes_removed = removed.len() as u64;
                    metrics::counter!(METRIC_TRIE_NODES_REMOVED, number_of_nodes_removed, "table" => stringify!($table));

                    for idx in removed {
                        stmt.execute(params![idx]).context("Deleting node")?;
                    }
                    Ok(())
                }

                /// Stores the node data for this trie and returns the index of the root.
                pub fn insert(tx: &Transaction<'_>, update: &TrieUpdate) -> anyhow::Result<u64> {
                    assert!(update.nodes_added.len() > 0, "Must have at least one node");

                    let mut stmt = tx
                        .inner()
                        .prepare_cached(concat!(
                            "INSERT INTO ",
                            stringify!($table),
                            " (hash, data) VALUES(?, ?) RETURNING idx",
                        ))
                        .context("Creating insert statement")?;

                    let mut to_insert = Vec::new();
                    let mut to_process = vec![NodeRef::Index(update.nodes_added.len() - 1)];

                    while let Some(node) = to_process.pop() {
                        // Only index variants need to be stored.
                        //
                        // Leaf nodes never get stored and a node having an
                        // ID indicates it has already been stored as part of a
                        // previous tree - and its children as well.
                        let NodeRef::Index(idx) = node else {
                            continue;
                        };

                        let (_, node) =
                            &update.nodes_added.get(idx).context("Node index missing")?;
                        to_insert.push(idx);

                        match node {
                            Node::Binary { left, right } => {
                                to_process.push(*left);
                                to_process.push(*right);
                            }
                            Node::Edge { child, .. } => {
                                to_process.push(*child);
                            }
                            // Leaves are not stored as separate nodes but are instead serialized in-line in their parents.
                            Node::LeafEdge { .. } | Node::LeafBinary { .. } => {}
                        }
                    }

                    let mut indices = HashMap::new();

                    // Reusable (and oversized) buffer for encoding.
                    let mut buffer = vec![0u8; 256];

                    // Insert nodes in reverse to ensure children always have an assigned index for the parent to use.
                    for idx in to_insert.into_iter().rev() {
                        let (hash, node) =
                            &update.nodes_added.get(idx).context("Node index missing")?;

                        let node = node.as_stored(&indices)?;

                        let length = node.encode(&mut buffer).context("Encoding node")?;

                        let storage_idx: u64 = stmt
                            .query_row(
                                params![&hash.as_be_bytes().as_slice(), &&buffer[..length]],
                                |row| row.get(0),
                            )
                            .context("Inserting node")?;

                        indices.insert(idx, storage_idx);

                        metrics::increment_counter!(METRIC_TRIE_NODES_ADDED, "table" => stringify!($table));
                    }

                    Ok(*indices
                        .get(&update.root_index().unwrap())
                        .expect("Root index must exist as we just inserted it"))
                }

                /// Returns the node with the given index.
                pub fn node(
                    tx: &Transaction<'_>,
                    index: u64,
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
                pub fn hash(tx: &Transaction<'_>, index: u64) -> anyhow::Result<Option<Felt>> {
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

/// The result of committing a Merkle tree.
#[derive(Default, Debug)]
pub struct TrieUpdate {
    /// New nodes added. Note that these may contain false positives if the
    /// mutations resulted in removing and then re-adding the same nodes within the tree.
    ///
    /// The last node is the root of the trie.
    pub nodes_added: Vec<(Felt, Node)>,
    // Nodes committed to storage that have been removed.
    pub nodes_removed: Vec<u64>,
}

impl TrieUpdate {
    pub fn root_index(&self) -> Option<usize> {
        if self.nodes_added.is_empty() {
            None
        } else {
            Some(self.nodes_added.len() - 1)
        }
    }

    pub fn root_hash(&self) -> Felt {
        self.nodes_added.last().map(|x| x.0).unwrap_or_default()
    }
}

#[derive(Clone, Debug)]
pub enum Node {
    Binary {
        left: NodeRef,
        right: NodeRef,
    },
    Edge {
        child: NodeRef,
        path: BitVec<u8, Msb0>,
    },
    LeafBinary,
    LeafEdge {
        path: BitVec<u8, Msb0>,
    },
}

#[derive(Copy, Clone, Debug)]
pub enum NodeRef {
    // A reference to a node that has already been committed to storage.
    StorageIndex(u64),
    // A reference to a node that has not yet been committed to storage.
    // The index within the `nodes_added` vector is used as a reference.
    Index(usize),
}

#[derive(Clone, Debug, PartialEq)]
pub enum StoredNode {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: BitVec<u8, Msb0> },
    LeafBinary,
    LeafEdge { path: BitVec<u8, Msb0> },
}

#[derive(Clone, Debug, bincode::Encode, bincode::BorrowDecode)]
enum StoredSerde {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: Vec<u8> },
    LeafBinary,
    LeafEdge { path: Vec<u8> },
}

impl StoredNode {
    const CODEC_CFG: bincode::config::Configuration = bincode::config::standard();

    /// Writes the [StoredNode] into `buffer` and returns the number of bytes written.
    fn encode(&self, buffer: &mut [u8]) -> Result<usize, bincode::error::EncodeError> {
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
        bincode::encode_into_slice(helper, buffer, Self::CODEC_CFG)
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
    fn into_binary(self) -> Option<(u64, u64)> {
        match self {
            Self::Binary { left, right } => Some((left, right)),
            _ => None,
        }
    }

    fn into_edge(self) -> Option<(u64, BitVec<u8, Msb0>)> {
        match self {
            Self::Edge { child, path } => Some((child, path)),
            _ => None,
        }
    }

    fn into_binary_leaf(self) -> Option<()> {
        match self {
            Self::LeafBinary => Some(()),
            _ => None,
        }
    }

    fn into_edge_leaf(self) -> Option<BitVec<u8, Msb0>> {
        match self {
            Self::LeafEdge { path } => Some(path),
            _ => None,
        }
    }
}

impl Node {
    fn as_stored(&self, storage_indices: &HashMap<usize, u64>) -> anyhow::Result<StoredNode> {
        let node = match self {
            Node::Binary { left, right } => {
                let left = match left {
                    NodeRef::StorageIndex(id) => *id,
                    NodeRef::Index(idx) => *storage_indices
                        .get(idx)
                        .context("Left child index missing")?,
                };

                let right = match right {
                    NodeRef::StorageIndex(id) => *id,
                    NodeRef::Index(idx) => *storage_indices
                        .get(idx)
                        .context("Right child index missing")?,
                };

                StoredNode::Binary { left, right }
            }
            Node::Edge { child, path } => {
                let child = match child {
                    NodeRef::StorageIndex(id) => id,
                    NodeRef::Index(idx) => {
                        storage_indices.get(idx).context("Child index missing")?
                    }
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
        let mut db = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = db.transaction().unwrap();

        let result = class_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, None);

        insert_class_root(&tx, BlockNumber::GENESIS, Some(123)).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));

        insert_class_root(&tx, BlockNumber::GENESIS + 1, Some(456)).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 1).unwrap();
        assert_eq!(result, Some(456));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 2).unwrap();
        assert_eq!(result, Some(456));

        insert_class_root(&tx, BlockNumber::GENESIS + 10, Some(789)).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS + 9).unwrap();
        assert_eq!(result, Some(456));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 10).unwrap();
        assert_eq!(result, Some(789));
        let result = class_root_index(&tx, BlockNumber::GENESIS + 11).unwrap();
        assert_eq!(result, Some(789));

        insert_class_root(&tx, BlockNumber::GENESIS + 12, None).unwrap();
        let result = class_root_index(&tx, BlockNumber::GENESIS + 12).unwrap();
        assert_eq!(result, None);
        let result = class_root_index(&tx, BlockNumber::GENESIS + 13).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn storage_roots() {
        let mut db = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = db.transaction().unwrap();

        let result = storage_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, None);

        insert_storage_root(&tx, BlockNumber::GENESIS, Some(123)).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));

        insert_storage_root(&tx, BlockNumber::GENESIS + 1, Some(456)).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS).unwrap();
        assert_eq!(result, Some(123));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 1).unwrap();
        assert_eq!(result, Some(456));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 2).unwrap();
        assert_eq!(result, Some(456));

        insert_storage_root(&tx, BlockNumber::GENESIS + 10, Some(789)).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 9).unwrap();
        assert_eq!(result, Some(456));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 10).unwrap();
        assert_eq!(result, Some(789));
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 11).unwrap();
        assert_eq!(result, Some(789));

        insert_storage_root(&tx, BlockNumber::GENESIS + 12, None).unwrap();
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 12).unwrap();
        assert_eq!(result, None);
        let result = storage_root_index(&tx, BlockNumber::GENESIS + 13).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn contract_roots() {
        let mut db = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
        let tx = db.transaction().unwrap();

        let c1 = contract_address_bytes!(b"first");
        let c2 = contract_address_bytes!(b"second");

        // Simplest trie node setup so we can test the fetching of contract root hashes.
        let root0 = contract_root_bytes!(b"root 0");
        let root_node = Node::LeafBinary;
        let nodes = vec![(root0.0, root_node.clone())];
        let update = TrieUpdate {
            nodes_added: nodes,
            ..Default::default()
        };

        let idx0 = trie_contracts::insert(&tx, &update).unwrap();

        let result1 = contract_root_index(&tx, BlockNumber::GENESIS, c1).unwrap();
        assert_eq!(result1, None);

        insert_contract_root(&tx, BlockNumber::GENESIS, c1, Some(idx0)).unwrap();
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS, c1).unwrap();
        let result2 = contract_root_index(&tx, BlockNumber::GENESIS, c2).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS, c1).unwrap();
        let hash2 = contract_root(&tx, BlockNumber::GENESIS, c2).unwrap();
        assert_eq!(result1, Some(idx0));
        assert_eq!(result2, None);
        assert_eq!(hash1, Some(root0));
        assert_eq!(hash2, None);

        let root1 = contract_root_bytes!(b"root 1");
        let nodes = vec![(root1.0, root_node.clone())];
        let update = TrieUpdate {
            nodes_added: nodes,
            ..Default::default()
        };

        let idx1 = trie_contracts::insert(&tx, &update).unwrap();

        insert_contract_root(&tx, BlockNumber::GENESIS + 1, c1, Some(idx1)).unwrap();
        insert_contract_root(&tx, BlockNumber::GENESIS + 1, c2, Some(888)).unwrap();
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
        let nodes = vec![(root2.0, root_node.clone())];
        let update = TrieUpdate {
            nodes_added: nodes,
            ..Default::default()
        };
        let idx2 = trie_contracts::insert(&tx, &update).unwrap();

        insert_contract_root(&tx, BlockNumber::GENESIS + 10, c1, Some(idx2)).unwrap();
        insert_contract_root(&tx, BlockNumber::GENESIS + 11, c2, Some(999)).unwrap();
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

        insert_contract_root(&tx, BlockNumber::GENESIS + 12, c1, None).unwrap();
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS + 10, c1).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 10, c1).unwrap();
        assert_eq!(result1, Some(idx2));
        assert_eq!(hash1, Some(root2));
        let result1 = contract_root_index(&tx, BlockNumber::GENESIS + 12, c1).unwrap();
        let hash1 = contract_root(&tx, BlockNumber::GENESIS + 12, c1).unwrap();
        assert_eq!(result1, None);
        assert_eq!(hash1, None);
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
                let tx = crate::Transaction::new(tx);

                let update = TrieUpdate {
                    nodes_added: vec![(
                        felt_bytes!(b"root"),
                        Node::Binary {
                            left: NodeRef::Index(5),
                            right: NodeRef::Index(7),
                        },
                    )],
                    nodes_removed: Default::default(),
                };

                test_table::insert(&tx, &update).unwrap_err();
            }

            #[test]
            fn binary() {
                let mut db = setup_db();
                let tx = db.transaction().unwrap();
                let tx = crate::Transaction::new(tx);

                let root = felt_bytes!(b"root");
                let update = TrieUpdate {
                    nodes_added: vec![
                        (
                            felt_bytes!(b"exists"),
                            Node::Edge {
                                child: NodeRef::Index(5),
                                path: bitvec::bitvec![u8, Msb0; 251; 1],
                            },
                        ),
                        (
                            root,
                            Node::Binary {
                                left: NodeRef::Index(5),
                                right: NodeRef::Index(0),
                            },
                        ),
                    ],
                    nodes_removed: Default::default(),
                };

                test_table::insert(&tx, &update).unwrap_err();
            }

            #[test]
            fn edge() {
                let mut db = setup_db();
                let tx = db.transaction().unwrap();
                let tx = crate::Transaction::new(tx);

                let root = felt_bytes!(b"root");
                let update = TrieUpdate {
                    nodes_added: vec![(
                        root,
                        Node::Edge {
                            child: NodeRef::Index(5),
                            path: bitvec::bitvec![u8, Msb0; 251; 1],
                        },
                    )],
                    nodes_removed: Default::default(),
                };

                test_table::insert(&tx, &update).unwrap_err();
            }
        }

        #[test]
        fn one_of_each_node() {
            // Create an (unrealistic) tree containing each of the node types and ensure
            // the tree and its hashes are retrieved accurately.
            let mut db = setup_db();
            let tx = db.transaction().unwrap();
            let tx = crate::Transaction::new(tx);

            let edge_leaf_hash = felt_bytes!(b"edge leaf");
            let edge_leaf_node = Node::LeafEdge {
                path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1],
            };

            let binary_leaf_hash = felt_bytes!(b"binary leaf");
            let binary_leaf_node = Node::LeafBinary;

            let edge_hash = felt_bytes!(b"edge");
            let edge_node = Node::Edge {
                child: NodeRef::Index(1),
                path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1],
            };

            let root_hash = felt_bytes!(b"root");
            let root_node = Node::Binary {
                left: NodeRef::Index(2),
                right: NodeRef::Index(0),
            };

            let update = TrieUpdate {
                nodes_added: vec![
                    (edge_leaf_hash, edge_leaf_node),
                    (binary_leaf_hash, binary_leaf_node),
                    (edge_hash, edge_node),
                    (root_hash, root_node),
                ],
                nodes_removed: Default::default(),
            };

            let root_idx = test_table::insert(&tx, &update).unwrap();

            // Root node
            let hash = test_table::hash(&tx, root_idx).unwrap();
            assert_eq!(hash, Some(root_hash));
            let node = test_table::node(&tx, root_idx).unwrap().unwrap();
            let (left, right) = node.into_binary().unwrap();

            // Right child is the edge leaf
            let hash = test_table::hash(&tx, right).unwrap();
            assert_eq!(hash, Some(edge_leaf_hash));
            let node = test_table::node(&tx, right).unwrap().unwrap();
            let path = node.into_edge_leaf().unwrap();
            assert_eq!(path, bitvec::bitvec![u8, Msb0; 1,0,1,1,1]);

            // Left child is the edge node
            let hash = test_table::hash(&tx, left).unwrap();
            assert_eq!(hash, Some(edge_hash));
            let node = test_table::node(&tx, left).unwrap().unwrap();
            let (child, path) = node.into_edge().unwrap();
            assert_eq!(path, bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1]);

            // Edge's child is the binary leaf
            let hash = test_table::hash(&tx, child).unwrap();
            assert_eq!(hash, Some(binary_leaf_hash));
            let node = test_table::node(&tx, child).unwrap().unwrap();
            node.into_binary_leaf().unwrap();
        }

        #[test]
        fn removed_nodes() {
            let mut db = setup_db();
            let tx = db.transaction().unwrap();
            let tx = crate::Transaction::new(tx);

            let update = TrieUpdate {
                nodes_added: vec![(
                    felt_bytes!(b"root"),
                    Node::LeafEdge {
                        path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1],
                    },
                )],
                nodes_removed: Default::default(),
            };

            let root_idx = test_table::insert(&tx, &update).unwrap();

            test_table::remove(&tx, &[root_idx]).unwrap();
            assert!(test_table::node(&tx, root_idx).unwrap().is_none());
        }

        #[test]
        fn id_children() {
            // Insert nodes which use ids as children instead of indexes.
            // The ids don't actually need to point to real nodes since this
            // isn't enforced within the db.
            let mut db = setup_db();
            let tx = db.transaction().unwrap();
            let tx = crate::Transaction::new(tx);

            let edge_hash = felt_bytes!(b"edge");
            let edge_node = Node::Edge {
                child: NodeRef::StorageIndex(123),
                path: bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1],
            };

            let binary_hash0 = felt_bytes!(b"binary");
            let binary_node0 = Node::Binary {
                left: NodeRef::StorageIndex(456),
                right: NodeRef::StorageIndex(777),
            };

            let root_hash = felt_bytes!(b"root");
            let root_node = Node::Binary {
                left: NodeRef::Index(0),
                right: NodeRef::Index(1),
            };

            let update = TrieUpdate {
                nodes_added: vec![
                    (edge_hash, edge_node),
                    (binary_hash0, binary_node0),
                    (root_hash, root_node),
                ],
                nodes_removed: Default::default(),
            };

            let root_idx = test_table::insert(&tx, &update).unwrap();

            // Root node
            let hash = test_table::hash(&tx, root_idx).unwrap();
            assert_eq!(hash, Some(root_hash));
            let node = test_table::node(&tx, root_idx).unwrap().unwrap();
            let (left, right) = node.into_binary().unwrap();

            // Right child is the binary node
            let hash = test_table::hash(&tx, right).unwrap();
            assert_eq!(hash, Some(binary_hash0));
            let node = test_table::node(&tx, right).unwrap().unwrap();
            let children = node.into_binary().unwrap();
            assert_eq!(children, (456, 777));

            // Left child is the edge node
            let hash = test_table::hash(&tx, left).unwrap();
            assert_eq!(hash, Some(edge_hash));
            let node = test_table::node(&tx, left).unwrap().unwrap();
            let (child, path) = node.into_edge().unwrap();
            assert_eq!(path, bitvec::bitvec![u8, Msb0; 1,0,1,1,1,0,0,0,0,0,1,1]);
            assert_eq!(child, 123);
        }
    }

    #[test]
    fn contract_state_hash() {
        let mut db = crate::StorageBuilder::in_memory()
            .unwrap()
            .connection()
            .unwrap();
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
