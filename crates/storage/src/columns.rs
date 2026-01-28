use rust_rocksdb::DBCompressionType;

#[derive(Clone, Debug)]
pub(crate) struct Column {
    pub name: &'static str,
}

impl Column {
    pub const fn new(name: &'static str) -> Self {
        Self { name }
    }

    pub fn options(&self) -> rust_rocksdb::Options {
        let mut options = rust_rocksdb::Options::default();
        options.optimize_for_point_lookup(8);
        options.set_compression_type(DBCompressionType::Zstd);
        options
    }
}

pub(crate) const COLUMNS: &[Column] = &[
    crate::connection::TRIE_CLASS_HASH_COLUMN,
    crate::connection::TRIE_CLASS_NODE_COLUMN,
    crate::connection::TRIE_CONTRACT_HASH_COLUMN,
    crate::connection::TRIE_CONTRACT_NODE_COLUMN,
    crate::connection::TRIE_STORAGE_HASH_COLUMN,
    crate::connection::TRIE_STORAGE_NODE_COLUMN,
];
