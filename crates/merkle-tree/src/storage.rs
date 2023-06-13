use pathfinder_common::trie::TrieNode;
use pathfinder_storage::{ClassTrieReader, ContractTrieReader, StorageTrieReader};
use stark_hash::Felt;

/// Read-only storage used by the [Merkle tree](crate::tree::MerkleTree).
pub trait Storage {
    fn get(&self, node: &Felt) -> anyhow::Result<Option<TrieNode>>;
}

impl<'tx> Storage for ClassTrieReader<'tx> {
    fn get(&self, node: &Felt) -> anyhow::Result<Option<TrieNode>> {
        ClassTrieReader::get(self, node)
    }
}

impl<'tx> Storage for StorageTrieReader<'tx> {
    fn get(&self, node: &Felt) -> anyhow::Result<Option<TrieNode>> {
        self.get(node)
    }
}

impl<'tx> Storage for ContractTrieReader<'tx> {
    fn get(&self, node: &Felt) -> anyhow::Result<Option<TrieNode>> {
        self.get(node)
    }
}
