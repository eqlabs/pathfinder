//! A Bloom filter is a space-efficient probabilistic data structure that
//! is used to test whether an element is a member of a set. An empty Bloom
//! filter is a bit array of m bits, all set to 0. It is equipped with k
//! different hash functions, which map set elements to one of the m possible
//! array positions. To check whether an element is in the set, the element is
//! hashed k times and the bits at the resulting positions are checked. If all k
//! bits are set to 1, the element is considered to be in the set (false
//! positives are possible). In our case, each block is a set with its own
//! [`BloomFilter`] and the elements are block events' keys and contract
//! addresses.
//!
//! When considering scenarios where keys need to be checked for large ranges
//! of blocks, it can certainly take a long time if [`BloomFilter`]s for each
//! block are loaded and checked against one by one. A possible optimization is
//! to store aggregates of [`BloomFilter`]s for ranges of blocks and, once keys
//! need to be checked for that range, this [`AggregateBloom`] filter can
//! be loaded and checked against in a single shot.
//!
//! Example: A key K1 that is mapped to three (out of *eight) indices of the
//! bloom filter, needs to be added to an aggregate bloom filter for a range
//! of *ten blocks. (*these are illustratory numbers, in practice much larger
//! values are used).
//!
//! We start with an empty aggregate filter, an 8x10 bitmap full of zeroes. Rows
//! of this matrix represent bloom filter indices that keys can be mapped to
//! whereas the columns represent the blocks within the range for which the
//! aggregate bloom filter is used.
//!
//! HashFn(K1) = [0, 1, 0, 1, 1, 0, 0, 0]
//!
//! We are inserting K1 as a part of the first block. In order to insert the key
//! into the aggregate, we first rotate it clockwise by 90 degrees (turning it
//! from a row vector into a column vector). Then, we set the first bit (since
//! we are adding to the first block) of rows 1, 3 and 4 (zero based) because
//! bloom filter hash functions map K1 to these indices. After this, we are left
//! with the following bitmap:
//!
//! [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//! [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
//!
//! which we can now store. Next, to check if K1 has been added to any of the
//! blocks, we perform the following steps:
//! 1) Load an [`AggregateBloom`] filter with the previously stored bitmap.
//! 2) Obtain the indices to which K1 maps to (1, 3 and 4 in this example),
//!    pluck out the corresponding rows and bitwise AND them together, leaving
//!    us with a 1x10 bit vector.
//! 3) Indices of bits that are set in the bit vector obtained through step 2)
//!    are block numbers to which K1 could have been added (or are false
//!    positives due to how Bloom filters work). In this example, the first bit
//!    will be set meaning block 0 could contain K1 (and it does since this is a
//!    very simplified example).
//!
//! This way, it's possible to quickly figure out which blocks correspond to a
//! specific set of keys without having to load and check each individual bloom
//! filter.

use std::sync::{Mutex, MutexGuard};

use bloomfilter::Bloom;
use cached::{Cached, SizedCache};
use pathfinder_common::{BlockNumber, ContractAddress, EventKey};
use pathfinder_crypto::Felt;

use crate::ReorgCounter;

// We're using the upper 4 bits of the 32 byte representation of a felt
// to store the index of the key in the values set in the Bloom filter.
// This allows for the maximum of 16 keys per event to be stored in the
// filter.
pub const EVENT_KEY_FILTER_LIMIT: usize = 16;

/// An aggregate of all Bloom filters for a given range of blocks.
/// Before being added to `AggregateBloom`, each [`BloomFilter`] is
/// rotated by 90 degrees (transposed).
#[derive(Debug)]
pub(crate) struct AggregateBloom {
    /// A [Self::BLOCK_RANGE_LEN] by [BloomFilter::BITVEC_LEN] matrix stored in
    /// a single array.
    bitmap: Vec<u8>,
    /// Block range for which the aggregate filter is constructed.
    block_range: std::ops::Range<BlockNumber>,
    next_block: BlockNumber,
}

impl AggregateBloom {
    // TODO:
    // Remove #[allow(dead_code)] when follow up is done.

    /// Maximum number of blocks to aggregate in a single `AggregateBloom`.
    const BLOCK_RANGE_LEN: u64 = 32_768;
    const BLOCK_RANGE_BYTES: u64 = Self::BLOCK_RANGE_LEN / 8;

    /// Create a new `AggregateBloom` for the (`from_block`, `from_block +
    /// [Self::BLOCK_RANGE_LEN]`) range.
    #[allow(dead_code)]
    pub fn new(from_block: BlockNumber) -> Self {
        let bitmap = vec![0; (Self::BLOCK_RANGE_BYTES * BloomFilter::BITVEC_LEN) as usize];

        let to_block = from_block + Self::BLOCK_RANGE_LEN;

        Self {
            bitmap,
            block_range: from_block..to_block,
            next_block: from_block,
        }
    }

    #[allow(dead_code)]
    pub fn from_bytes(from_block: BlockNumber, bytes: Vec<u8>) -> Self {
        assert_eq!(
            bytes.len() as u64,
            Self::BLOCK_RANGE_BYTES * BloomFilter::BITVEC_LEN,
            "Bitmap size mismatch"
        );

        let to_block = from_block + Self::BLOCK_RANGE_LEN;

        Self {
            bitmap: bytes,
            block_range: from_block..to_block,
            next_block: from_block,
        }
    }

    #[allow(dead_code)]
    pub fn to_bytes(&self) -> &[u8] {
        &self.bitmap
    }

    /// Rotate the bloom filter by 90 degrees and add it to the aggregate.
    #[allow(dead_code)]
    pub fn add_bloom(
        &mut self,
        bloom: &BloomFilter,
        insert_pos: BlockNumber,
    ) -> Result<(), AddBloomError> {
        if !self.block_range.contains(&insert_pos) {
            return Err(AddBloomError::InvalidBlockNumber);
        }
        assert_eq!(self.next_block, insert_pos, "Unexpected insert position");
        assert_eq!(
            bloom.0.number_of_hash_functions(),
            BloomFilter::K_NUM,
            "Hash function count mismatch"
        );

        let bloom = bloom.0.bit_vec().to_bytes();
        assert_eq!(
            bloom.len() as u64,
            BloomFilter::BITVEC_BYTES,
            "Bit vector length mismatch"
        );

        let byte_index = (insert_pos.get() / 8) as usize;
        let bit_index = (insert_pos.get() % 8) as usize;
        for (i, bloom_byte) in bloom.iter().enumerate() {
            if *bloom_byte == 0 {
                continue;
            }

            let base = 8 * i;
            for j in 0..8 {
                let row_idx = base + j;
                let idx = Self::bitmap_index_at(row_idx, byte_index);
                self.bitmap[idx] |= ((bloom_byte >> (7 - j)) & 1) << bit_index;
            }
        }

        self.next_block += 1;
        if self.next_block >= self.block_range.end {
            tracing::info!(
                "Block limit reached for [{}, {}) range",
                self.block_range.start,
                self.block_range.end
            );
            return Err(AddBloomError::BlockLimitReached);
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub fn blocks_for_filter(&self, filter: &crate::EventFilter) -> Vec<BlockNumber> {
        let mut keys = vec![];

        if let Some(contract_address) = filter.contract_address {
            keys.push(contract_address.0);
        }
        filter.keys.iter().flatten().for_each(|k| keys.push(k.0));

        self.blocks_for_keys(keys)
    }

    #[allow(dead_code)]
    fn blocks_for_keys(&self, keys: Vec<Felt>) -> Vec<BlockNumber> {
        let mut block_matches = vec![];

        for k in keys {
            let mut row_to_check = vec![u8::MAX; Self::BLOCK_RANGE_BYTES as usize];

            let indices = BloomFilter::indices_for_key(&k);
            for row_idx in indices {
                for (col_idx, row_byte) in row_to_check.iter_mut().enumerate() {
                    let idx = Self::bitmap_index_at(row_idx, col_idx);
                    *row_byte &= self.bitmap[idx];
                }
            }

            for (col_idx, byte) in row_to_check.iter().enumerate() {
                if *byte == 0 {
                    continue;
                }

                for i in 0..8 {
                    if byte & (1 << i) != 0 {
                        block_matches.push(BlockNumber::new_or_panic((col_idx * 8 + i) as u64));
                    }
                }
            }
        }

        block_matches
    }

    #[allow(dead_code)]
    fn bitmap_index_at(row: usize, col: usize) -> usize {
        row * Self::BLOCK_RANGE_BYTES as usize + col
    }
}

#[derive(Debug)]
pub enum AddBloomError {
    BlockLimitReached,
    InvalidBlockNumber,
}

#[derive(Clone)]
pub(crate) struct BloomFilter(Bloom<Felt>);

impl BloomFilter {
    // The size of the bitmap used by the Bloom filter.
    const BITVEC_LEN: u64 = 16_384;
    // The size of the bitmap used by the Bloom filter (in bytes).
    const BITVEC_BYTES: u64 = Self::BITVEC_LEN / 8;
    // The number of hash functions used by the Bloom filter.
    // We need this value to be able to re-create the filter with the deserialized
    // bitmap.
    const K_NUM: u32 = 12;
    // The maximal number of items anticipated to be inserted into the Bloom filter.
    const ITEMS_COUNT: u32 = 1024;
    // The seed used by the hash functions of the filter.
    // This is a randomly generated vector of 32 bytes.
    const SEED: [u8; 32] = [
        0xef, 0x51, 0x88, 0x74, 0xef, 0x08, 0x3d, 0xf6, 0x7d, 0x7a, 0x93, 0xb7, 0xb3, 0x13, 0x1f,
        0x87, 0xd3, 0x26, 0xbd, 0x49, 0xc7, 0x18, 0xcc, 0xe5, 0xd7, 0xe8, 0xa0, 0xdb, 0xea, 0x80,
        0x67, 0x52,
    ];

    pub fn new() -> Self {
        let bloom = Bloom::new_with_seed(
            Self::BITVEC_BYTES as usize,
            Self::ITEMS_COUNT as usize,
            &Self::SEED,
        );
        assert_eq!(bloom.number_of_hash_functions(), Self::K_NUM);

        Self(bloom)
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Self {
        let bytes = zstd::bulk::decompress(bytes, Self::BITVEC_BYTES as usize * 2)
            .expect("Decompressing Bloom filter");
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let k1 = u64::from_le_bytes(Self::SEED[0..8].try_into().unwrap());
        let k2 = u64::from_le_bytes(Self::SEED[8..16].try_into().unwrap());
        let k3 = u64::from_le_bytes(Self::SEED[16..24].try_into().unwrap());
        let k4 = u64::from_le_bytes(Self::SEED[24..32].try_into().unwrap());
        let bloom = Bloom::from_existing(
            bytes,
            Self::BITVEC_BYTES * 8,
            Self::K_NUM,
            [(k1, k2), (k3, k4)],
        );
        Self(bloom)
    }

    pub fn to_compressed_bytes(&self) -> Vec<u8> {
        let bytes = self.to_bytes();
        zstd::bulk::compress(&bytes, 0).expect("Compressing Bloom filter")
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.bitmap()
    }

    fn set(&mut self, key: &Felt) {
        self.0.set(key);
    }

    pub fn set_address(&mut self, address: &ContractAddress) {
        self.set(&address.0);
    }

    pub fn set_keys(&mut self, keys: &[EventKey]) {
        for (i, key) in keys.iter().take(EVENT_KEY_FILTER_LIMIT).enumerate() {
            let mut key = key.0;
            key.as_mut_be_bytes()[0] |= (i as u8) << 4;
            self.set(&key);
        }
    }

    fn check(&self, key: &Felt) -> bool {
        self.0.check(key)
    }

    fn check_address(&self, address: &ContractAddress) -> bool {
        self.check(&address.0)
    }

    fn check_keys(&self, keys: &[Vec<EventKey>]) -> bool {
        keys.iter().enumerate().all(|(idx, keys)| {
            if keys.is_empty() {
                return true;
            };

            keys.iter().any(|key| {
                let mut key = key.0;
                key.as_mut_be_bytes()[0] |= (idx as u8) << 4;
                tracing::trace!(%idx, %key, "Checking key in filter");
                self.check(&key)
            })
        })
    }

    pub fn check_filter(&self, filter: &crate::EventFilter) -> bool {
        if let Some(contract_address) = filter.contract_address {
            if !self.check_address(&contract_address) {
                return false;
            }
        }

        self.check_keys(&filter.keys)
    }

    // Workaround to get the indices of the keys in the filter.
    // Needed because the `bloomfilter` crate doesn't provide a
    // way to get this information.
    fn indices_for_key(key: &Felt) -> Vec<usize> {
        // Use key on an empty Bloom filter
        let mut bloom = Self::new();
        bloom.set(key);

        bloom
            .0
            .bit_vec()
            .iter()
            .enumerate()
            .filter(|(_, bit)| *bit)
            .map(|(i, _)| i)
            .collect()
    }
}

type CacheKey = (crate::ReorgCounter, BlockNumber);
pub(crate) struct Cache(Mutex<SizedCache<CacheKey, BloomFilter>>);

impl Cache {
    pub fn with_size(size: usize) -> Self {
        Self(Mutex::new(SizedCache::with_size(size)))
    }

    fn locked_cache(&self) -> MutexGuard<'_, SizedCache<CacheKey, BloomFilter>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn get(
        &self,
        reorg_counter: ReorgCounter,
        block_number: BlockNumber,
    ) -> Option<BloomFilter> {
        self.locked_cache()
            .cache_get(&(reorg_counter, block_number))
            .cloned()
    }

    pub fn set(&self, reorg_counter: ReorgCounter, block_number: BlockNumber, bloom: BloomFilter) {
        self.locked_cache()
            .cache_set((reorg_counter, block_number), bloom);
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use pathfinder_common::felt;

    use super::*;

    const KEY: Felt = felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69ea");
    const KEY1: Felt = felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69eb");
    const KEY_NOT_IN_FILTER: Felt =
        felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69ec");

    #[test]
    fn set_and_check() {
        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);
        assert!(bloom.check(&KEY));
        assert!(!bloom.check(&KEY_NOT_IN_FILTER));
    }

    #[test]
    fn serialize_roundtrip() {
        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        let bytes = bloom.to_compressed_bytes();
        let bloom = BloomFilter::from_compressed_bytes(&bytes);
        assert!(bloom.check(&KEY));
        assert!(!bloom.check(&KEY_NOT_IN_FILTER));
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    fn add_bloom_and_check_single_block_found() {
        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);
        bloom.set(&KEY1);

        aggregate_bloom_filter
            .add_bloom(&bloom, from_block)
            .unwrap();

        let block_matches = aggregate_bloom_filter.blocks_for_keys(vec![KEY]);

        assert_eq!(block_matches, vec![from_block]);
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    fn add_blooms_and_check_multiple_blocks_found() {
        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        aggregate_bloom_filter
            .add_bloom(&bloom, from_block)
            .unwrap();
        aggregate_bloom_filter
            .add_bloom(&bloom, from_block + 1)
            .unwrap();

        let block_matches = aggregate_bloom_filter.blocks_for_keys(vec![KEY]);

        assert_eq!(block_matches, vec![from_block, from_block + 1]);
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    fn key_not_in_filter_returns_empty_vec() {
        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);
        bloom.set(&KEY1);

        aggregate_bloom_filter
            .add_bloom(&bloom, from_block)
            .unwrap();
        aggregate_bloom_filter
            .add_bloom(&bloom, from_block + 1)
            .unwrap();

        let block_matches_empty = aggregate_bloom_filter.blocks_for_keys(vec![KEY_NOT_IN_FILTER]);

        assert_eq!(block_matches_empty, Vec::<BlockNumber>::new());
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    fn serialize_aggregate_roundtrip() {
        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        aggregate_bloom_filter
            .add_bloom(&bloom, from_block)
            .unwrap();
        aggregate_bloom_filter
            .add_bloom(&bloom, from_block + 1)
            .unwrap();

        let bytes = aggregate_bloom_filter.to_bytes();
        let aggregate_bloom_filter = AggregateBloom::from_bytes(from_block, bytes.to_vec());

        let block_matches = aggregate_bloom_filter.blocks_for_keys(vec![KEY]);
        let block_matches_empty = aggregate_bloom_filter.blocks_for_keys(vec![KEY_NOT_IN_FILTER]);

        assert_eq!(block_matches, vec![from_block, from_block + 1]);
        assert_eq!(block_matches_empty, Vec::<BlockNumber>::new());
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    fn block_limit_reached_after_full_range() {
        impl AggregateBloom {
            /// Real [Self::add_bloom] makes this test last way to long
            fn add_bloom_mock(&mut self) {
                self.next_block += 1;
            }
        }

        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        for _ in from_block.get()..(AggregateBloom::BLOCK_RANGE_LEN - 1) {
            aggregate_bloom_filter.add_bloom_mock();
        }

        let last_block = from_block + AggregateBloom::BLOCK_RANGE_LEN - 1;
        assert_matches!(
            aggregate_bloom_filter.add_bloom(&bloom, last_block),
            Err(AddBloomError::BlockLimitReached)
        );
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    fn invalid_insert_pos() {
        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        aggregate_bloom_filter
            .add_bloom(&bloom, from_block)
            .unwrap();

        let invalid_insert_pos = from_block + AggregateBloom::BLOCK_RANGE_LEN;
        assert_matches!(
            aggregate_bloom_filter.add_bloom(&bloom, invalid_insert_pos),
            Err(AddBloomError::InvalidBlockNumber)
        );
    }

    #[test]
    #[cfg_attr(not(feature = "aggregate_bloom"), ignore)]
    #[should_panic]
    fn skipping_a_block_panics() {
        let from_block = BlockNumber::new_or_panic(0);
        let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        aggregate_bloom_filter
            .add_bloom(&bloom, from_block)
            .unwrap();

        let skipped_block = from_block + 2;
        aggregate_bloom_filter
            .add_bloom(&bloom, skipped_block)
            .unwrap();
    }
}
