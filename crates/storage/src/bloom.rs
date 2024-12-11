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

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use bloomfilter::Bloom;
use cached::{Cached, SizedCache};
use pathfinder_common::BlockNumber;
use pathfinder_crypto::Felt;

pub const BLOCK_RANGE_LEN: u64 = AggregateBloom::BLOCK_RANGE_LEN;

/// An aggregate of all Bloom filters for a given range of blocks.
/// Before being added to `AggregateBloom`, each [`BloomFilter`] is
/// rotated by 90 degrees (transposed).
#[derive(Clone)]
pub struct AggregateBloom {
    /// A [Self::BLOCK_RANGE_LEN] by [BloomFilter::BITVEC_LEN] matrix stored in
    /// a single array.
    bitmap: Vec<u8>,
    /// Starting (inclusive) block number for the range of blocks that this
    /// aggregate covers.
    pub from_block: BlockNumber,
    /// Ending (inclusive) block number for the range of blocks that this
    /// aggregate covers.
    pub to_block: BlockNumber,
}

impl AggregateBloom {
    /// Maximum number of blocks to aggregate in a single `AggregateBloom`.
    pub const BLOCK_RANGE_LEN: u64 = 8192;
    const BLOCK_RANGE_BYTES: u64 = Self::BLOCK_RANGE_LEN / 8;

    /// Create a new `AggregateBloom` for the (`from_block`, `from_block` +
    /// [`block_range_length`](Self::BLOCK_RANGE_LEN) - 1) range.
    pub fn new(from_block: BlockNumber) -> Self {
        let to_block = from_block + Self::BLOCK_RANGE_LEN - 1;
        let bitmap = vec![0; Self::BLOCK_RANGE_BYTES as usize * BloomFilter::BITVEC_LEN as usize];
        Self::from_parts(from_block, to_block, bitmap)
    }

    pub fn from_existing_compressed(
        from_block: BlockNumber,
        to_block: BlockNumber,
        compressed_bitmap: Vec<u8>,
    ) -> Self {
        let bitmap = zstd::bulk::decompress(
            &compressed_bitmap,
            AggregateBloom::BLOCK_RANGE_BYTES as usize * BloomFilter::BITVEC_LEN as usize,
        )
        .expect("Decompressing aggregate Bloom filter");

        Self::from_parts(from_block, to_block, bitmap)
    }

    fn from_parts(from_block: BlockNumber, to_block: BlockNumber, bitmap: Vec<u8>) -> Self {
        assert_eq!(from_block + Self::BLOCK_RANGE_LEN - 1, to_block);
        assert_eq!(
            bitmap.len() as u64,
            Self::BLOCK_RANGE_BYTES * BloomFilter::BITVEC_LEN
        );

        Self {
            bitmap,
            from_block,
            to_block,
        }
    }

    pub fn compress_bitmap(&self) -> Vec<u8> {
        zstd::bulk::compress(&self.bitmap, 10).expect("Compressing aggregate Bloom filter")
    }

    /// Rotate the [`BloomFilter`] by 90 degrees (transpose) and add it to the
    /// aggregate. It is up to the user to keep track of when the aggregate
    /// filter's block range has been exhausted and respond accordingly.
    pub fn add_bloom(&mut self, bloom: &BloomFilter, block_number: BlockNumber) {
        assert!(
            (self.from_block..=self.to_block).contains(&block_number),
            "Block number {} is not in the range {}..={}",
            block_number,
            self.from_block,
            self.to_block
        );
        assert_eq!(bloom.0.number_of_hash_functions(), BloomFilter::K_NUM);

        let bloom = bloom.0.bit_vec().to_bytes();
        assert_eq!(bloom.len() as u64, BloomFilter::BITVEC_BYTES);

        let relative_block_number = block_number.get() - self.from_block.get();
        let byte_idx = (relative_block_number / 8) as usize;
        let bit_idx = (relative_block_number % 8) as usize;
        for (i, bloom_byte) in bloom.iter().enumerate() {
            if *bloom_byte == 0 {
                continue;
            }

            let base = 8 * i;
            for j in 0..8 {
                let row_idx = base + j;
                *self.bitmap_at_mut(row_idx, byte_idx) |= ((bloom_byte >> (7 - j)) & 1) << bit_idx;
            }
        }
    }

    /// Returns a set of [block numbers](BlockNumber) for which the given keys
    /// are present in the aggregate.
    pub fn blocks_for_keys(&self, keys: &[Felt]) -> BTreeSet<BlockNumber> {
        if keys.is_empty() {
            return self.all_blocks();
        }

        let mut block_matches = BTreeSet::new();

        for k in keys {
            let mut row_to_check = vec![u8::MAX; Self::BLOCK_RANGE_BYTES as usize];

            let indices = BloomFilter::indices_for_key(k);
            for row_idx in indices {
                for (col_idx, row_byte) in row_to_check.iter_mut().enumerate() {
                    *row_byte &= self.bitmap_at(row_idx, col_idx);
                }
            }

            for (col_idx, byte) in row_to_check.iter().enumerate() {
                if *byte == 0 {
                    continue;
                }

                for i in 0..8 {
                    if byte & (1 << i) != 0 {
                        let match_number = self.from_block + col_idx as u64 * 8 + i as u64;
                        block_matches.insert(match_number);
                    }
                }
            }
        }

        block_matches
    }

    pub(super) fn all_blocks(&self) -> BTreeSet<BlockNumber> {
        (self.from_block.get()..=self.to_block.get())
            .map(BlockNumber::new_or_panic)
            .collect()
    }

    fn bitmap_at(&self, row: usize, col: usize) -> u8 {
        let idx = row * Self::BLOCK_RANGE_BYTES as usize + col;
        self.bitmap[idx]
    }

    fn bitmap_at_mut(&mut self, row: usize, col: usize) -> &mut u8 {
        let idx = row * Self::BLOCK_RANGE_BYTES as usize + col;
        &mut self.bitmap[idx]
    }
}

impl std::fmt::Debug for AggregateBloom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::hash::{DefaultHasher, Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.bitmap.hash(&mut hasher);
        let bitmap_hash = hasher.finish();

        f.debug_struct("AggregateBloom")
            .field("from_block", &self.from_block)
            .field("to_block", &self.to_block)
            .field("bitmap_hash", &format!("{:#x}", bitmap_hash))
            .finish()
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    from_block: BlockNumber,
    to_block: BlockNumber,
}

/// A cache for [`AggregateBloom`] filters. It is very expensive to clone these
/// filters, so we store them in an [`Arc`] and clone it instead.
pub(crate) struct AggregateBloomCache(Mutex<SizedCache<CacheKey, Arc<AggregateBloom>>>);

impl AggregateBloomCache {
    pub fn with_size(size: usize) -> Self {
        Self(Mutex::new(SizedCache::with_size(size)))
    }

    pub fn reset(&self) {
        self.0.lock().unwrap().cache_reset();
    }

    pub fn get_many(
        &self,
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> Vec<Arc<AggregateBloom>> {
        let mut cache = self.0.lock().unwrap();

        let from_block = from_block.get();
        let to_block = to_block.get();

        // Align to the nearest lower multiple of BLOCK_RANGE_LEN.
        let from_block_aligned = from_block - from_block % AggregateBloom::BLOCK_RANGE_LEN;
        // Align to the nearest higher multiple of BLOCK_RANGE_LEN, then subtract 1
        // (zero based indexing).
        let to_block_aligned = to_block + AggregateBloom::BLOCK_RANGE_LEN
            - (to_block % AggregateBloom::BLOCK_RANGE_LEN)
            - 1;

        (from_block_aligned..=to_block_aligned)
            .step_by(AggregateBloom::BLOCK_RANGE_LEN as usize)
            .map(|from| {
                let to = from + AggregateBloom::BLOCK_RANGE_LEN - 1;
                (
                    BlockNumber::new_or_panic(from),
                    BlockNumber::new_or_panic(to),
                )
            })
            .filter_map(|(from_block, to_block)| {
                let k = CacheKey {
                    from_block,
                    to_block,
                };
                cache.cache_get(&k).map(Arc::clone)
            })
            .collect()
    }

    pub fn set_many(&self, filters: &[Arc<AggregateBloom>]) {
        let mut cache = self.0.lock().unwrap();
        filters.iter().for_each(|filter| {
            let k = CacheKey {
                from_block: filter.from_block,
                to_block: filter.to_block,
            };
            cache.cache_set(k, Arc::clone(filter));
        });
    }
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

    pub fn set(&mut self, key: &Felt) {
        self.0.set(key);
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

#[cfg(test)]
mod tests {
    use pathfinder_common::felt;

    use super::*;

    const KEY: Felt = felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69ea");
    const KEY1: Felt = felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69eb");
    const KEY_NOT_IN_FILTER: Felt =
        felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69ec");

    mod filters {
        use super::*;

        #[test]
        fn add_bloom_and_check_single_block_found() {
            let from_block = BlockNumber::new_or_panic(0);
            let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

            let mut bloom = BloomFilter::new();
            bloom.set(&KEY);
            bloom.set(&KEY1);

            aggregate_bloom_filter.add_bloom(&bloom, from_block);

            let block_matches = aggregate_bloom_filter.blocks_for_keys(&[KEY]);
            let expected = BTreeSet::from_iter(vec![from_block]);
            assert_eq!(block_matches, expected);
        }

        #[test]
        fn add_blooms_and_check_multiple_blocks_found() {
            let from_block = BlockNumber::new_or_panic(0);
            let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

            let mut bloom = BloomFilter::new();
            bloom.set(&KEY);

            aggregate_bloom_filter.add_bloom(&bloom, from_block);
            aggregate_bloom_filter.add_bloom(&bloom, from_block + 1);

            let block_matches = aggregate_bloom_filter.blocks_for_keys(&[KEY]);
            let expected = BTreeSet::from_iter(vec![from_block, from_block + 1]);
            assert_eq!(block_matches, expected);
        }

        #[test]
        fn key_not_in_filter_returns_empty_vec() {
            let from_block = BlockNumber::new_or_panic(0);
            let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

            let mut bloom = BloomFilter::new();
            bloom.set(&KEY);
            bloom.set(&KEY1);

            aggregate_bloom_filter.add_bloom(&bloom, from_block);
            aggregate_bloom_filter.add_bloom(&bloom, from_block + 1);

            let block_matches_empty = aggregate_bloom_filter.blocks_for_keys(&[KEY_NOT_IN_FILTER]);
            assert_eq!(block_matches_empty, BTreeSet::new());
        }

        #[test]
        fn serialize_aggregate_roundtrip() {
            let from_block = BlockNumber::new_or_panic(0);
            let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

            let mut bloom = BloomFilter::new();
            bloom.set(&KEY);

            aggregate_bloom_filter.add_bloom(&bloom, from_block);
            aggregate_bloom_filter.add_bloom(&bloom, from_block + 1);

            let compressed_bitmap = aggregate_bloom_filter.compress_bitmap();
            let mut decompressed = AggregateBloom::from_existing_compressed(
                aggregate_bloom_filter.from_block,
                aggregate_bloom_filter.to_block,
                compressed_bitmap,
            );
            decompressed.add_bloom(&bloom, from_block + 2);

            let block_matches = decompressed.blocks_for_keys(&[KEY]);
            let expected = BTreeSet::from_iter(vec![from_block, from_block + 1, from_block + 2]);
            assert_eq!(block_matches, expected,);

            let block_matches_empty = decompressed.blocks_for_keys(&[KEY_NOT_IN_FILTER]);
            assert_eq!(block_matches_empty, BTreeSet::new());
        }

        #[test]
        #[should_panic]
        fn invalid_insert_pos() {
            let from_block = BlockNumber::new_or_panic(0);
            let mut aggregate_bloom_filter = AggregateBloom::new(from_block);

            let mut bloom = BloomFilter::new();
            bloom.set(&KEY);

            aggregate_bloom_filter.add_bloom(&bloom, from_block);

            let invalid_insert_pos = from_block + AggregateBloom::BLOCK_RANGE_LEN;
            aggregate_bloom_filter.add_bloom(&bloom, invalid_insert_pos);
        }
    }

    mod cache {
        use super::*;

        // Tests only use ranges so no need to compare bitmap.
        impl PartialEq for AggregateBloom {
            fn eq(&self, other: &Self) -> bool {
                self.from_block == other.from_block && self.to_block == other.to_block
            }
        }

        #[test]
        fn set_then_get_many_aligned() {
            let cache = AggregateBloomCache::with_size(2);

            let first_range_start = BlockNumber::GENESIS;
            let second_range_start = BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN;
            let second_range_end = second_range_start + AggregateBloom::BLOCK_RANGE_LEN - 1;

            let filters = vec![
                Arc::new(AggregateBloom::new(first_range_start)),
                Arc::new(AggregateBloom::new(second_range_start)),
            ];

            cache.set_many(&filters);

            let retrieved = cache.get_many(first_range_start, second_range_end);

            assert_eq!(retrieved, filters);
        }

        #[test]
        fn set_then_get_many_unaligned() {
            let cache = AggregateBloomCache::with_size(2);

            let first_range_start = BlockNumber::GENESIS;
            let second_range_start = BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN;

            let filters = vec![
                Arc::new(AggregateBloom::new(first_range_start)),
                Arc::new(AggregateBloom::new(second_range_start)),
            ];

            let start = first_range_start + 15;
            let end = second_range_start + 15;

            cache.set_many(&filters);

            let retrieved = cache.get_many(start, end);

            assert_eq!(retrieved, filters);
        }

        #[test]
        fn filters_outside_of_range_not_returned() {
            let cache = AggregateBloomCache::with_size(4);

            let filters = vec![
                Arc::new(AggregateBloom::new(BlockNumber::GENESIS)),
                Arc::new(AggregateBloom::new(
                    BlockNumber::GENESIS + AggregateBloom::BLOCK_RANGE_LEN,
                )),
                Arc::new(AggregateBloom::new(
                    BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN,
                )),
                Arc::new(AggregateBloom::new(
                    BlockNumber::GENESIS + 3 * AggregateBloom::BLOCK_RANGE_LEN,
                )),
            ];

            cache.set_many(&filters);

            let first_range_start = BlockNumber::GENESIS;
            let second_range_end = BlockNumber::GENESIS + 2 * AggregateBloom::BLOCK_RANGE_LEN - 1;

            let retrieved = cache.get_many(first_range_start, second_range_end);

            assert_eq!(retrieved, filters[0..2].to_vec());
        }
    }
}
