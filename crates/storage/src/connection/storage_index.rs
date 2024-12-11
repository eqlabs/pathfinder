/// A newtype for the storage index of a trie node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrieStorageIndex(u64);

impl TrieStorageIndex {
    /// Create a new StorageIndex.
    pub fn new(index: u64) -> Self {
        Self(index)
    }

    /// Get the inner u64 value.
    pub fn get(&self) -> u64 {
        self.0
    }
}
