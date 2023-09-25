use pathfinder_storage::{ClassTrieReader, ContractTrieReader, StorageTrieReader, StoredNode};
use stark_hash::Felt;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    fn get(&self, index: u32) -> anyhow::Result<Option<StoredNode>>;

    fn hash(&self, index: u32) -> anyhow::Result<Option<Felt>>;
}

impl<'tx> Storage for ClassTrieReader<'tx> {
    fn get(&self, index: u32) -> anyhow::Result<Option<StoredNode>> {
        self.get(index)
    }

    fn hash(&self, index: u32) -> anyhow::Result<Option<Felt>> {
        self.hash(index)
    }
}

impl<'tx> Storage for StorageTrieReader<'tx> {
    fn get(&self, index: u32) -> anyhow::Result<Option<StoredNode>> {
        self.get(index)
    }

    fn hash(&self, index: u32) -> anyhow::Result<Option<Felt>> {
        self.hash(index)
    }
}

impl<'tx> Storage for ContractTrieReader<'tx> {
    fn get(&self, index: u32) -> anyhow::Result<Option<StoredNode>> {
        self.get(index)
    }

    fn hash(&self, index: u32) -> anyhow::Result<Option<Felt>> {
        self.hash(index)
    }
}
