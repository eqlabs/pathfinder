use bitvec::prelude::*;
use pathfinder_crypto::Felt;
use pathfinder_storage::StoredNode;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    /// Returns the node stored at the given index.
    fn get(&self, index: u64) -> anyhow::Result<Option<StoredNode>>;
    /// Returns the hash of the node at the given index.
    fn hash(&self, index: u64) -> anyhow::Result<Option<Felt>>;
    /// Returns the value of the leaf at the given path.
    fn leaf(&self, path: &BitSlice<u8, Msb0>) -> anyhow::Result<Option<Felt>>;
}
