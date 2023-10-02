use pathfinder_storage::StoredNode;
use stark_hash::Felt;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    fn get(&self, index: u32) -> anyhow::Result<Option<StoredNode>>;

    fn hash(&self, index: u32) -> anyhow::Result<Option<Felt>>;
}
