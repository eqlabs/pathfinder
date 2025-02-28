use bitvec::prelude::*;
use pathfinder_crypto::Felt;
use pathfinder_storage::StoredNode;
// Re-export the `TrieStorageIndex` type for use in the `tree` module.
pub(crate) use pathfinder_storage::TrieStorageIndex;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    /// Returns the node stored at the given index.
    fn get(&self, index: TrieStorageIndex) -> anyhow::Result<Option<StoredNode>>;
    /// Returns the hash of the node at the given index.
    fn hash(&self, index: TrieStorageIndex) -> anyhow::Result<Option<Felt>>;
    /// Returns the value of the leaf at the given path.
    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<Felt>>;
}
