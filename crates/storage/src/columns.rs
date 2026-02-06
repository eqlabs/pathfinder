use rust_rocksdb::DBCompressionType;

#[derive(Clone, Debug)]
pub(crate) struct Column {
    pub name: &'static str,
    key_prefix_length: Option<usize>,
    point_lookup: bool,
}

impl Column {
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            key_prefix_length: None,
            point_lookup: false,
        }
    }

    pub fn options(&self) -> rust_rocksdb::Options {
        let mut options = rust_rocksdb::Options::default();
        options.set_bottommost_compression_type(DBCompressionType::Zstd);
        if self.point_lookup {
            options.optimize_for_point_lookup(8);
        }
        if let Some(prefix_length) = self.key_prefix_length {
            options.set_prefix_extractor(rust_rocksdb::SliceTransform::create_fixed_prefix(
                prefix_length,
            ));
        }
        options
    }

    pub const fn with_prefix_length(self, prefix_length: usize) -> Self {
        Self {
            key_prefix_length: Some(prefix_length),
            ..self
        }
    }

    pub const fn with_point_lookup(self) -> Self {
        Self {
            point_lookup: true,
            ..self
        }
    }
}

pub(crate) const COLUMNS: &[Column] = &[
    crate::connection::TRIE_CLASS_HASH_COLUMN,
    crate::connection::TRIE_CLASS_NODE_COLUMN,
    crate::connection::TRIE_CONTRACT_HASH_COLUMN,
    crate::connection::TRIE_CONTRACT_NODE_COLUMN,
    crate::connection::TRIE_STORAGE_HASH_COLUMN,
    crate::connection::TRIE_STORAGE_NODE_COLUMN,
    crate::connection::STATE_UPDATES_COLUMN,
    crate::connection::STORAGE_UPDATES_COLUMN,
    crate::connection::NONCE_UPDATES_COLUMN,
];
