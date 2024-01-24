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

#[derive(Clone)]
pub(crate) struct BloomFilter(Bloom<Felt>);

impl BloomFilter {
    // The size of the bitmap used by the Bloom filter (in bytes).
    const BITMAP_BYTES: u64 = 2048;
    // The maximal number of items anticipated to be inserted into the Bloom filter.
    const ITEMS_COUNT: u32 = 1024;
    // The number of hash functions used by the Bloom filter.
    // We need this value to be able to re-create the filter with the deserialized bitmap.
    const K_NUM: u32 = 12;
    // The seed used by the hash functions of the filter.
    // This is a randomly generated vector of 32 bytes.
    const SEED: [u8; 32] = [
        0xef, 0x51, 0x88, 0x74, 0xef, 0x08, 0x3d, 0xf6, 0x7d, 0x7a, 0x93, 0xb7, 0xb3, 0x13, 0x1f,
        0x87, 0xd3, 0x26, 0xbd, 0x49, 0xc7, 0x18, 0xcc, 0xe5, 0xd7, 0xe8, 0xa0, 0xdb, 0xea, 0x80,
        0x67, 0x52,
    ];

    pub fn new() -> Self {
        let bloom = Bloom::new_with_seed(
            Self::BITMAP_BYTES as usize,
            Self::ITEMS_COUNT as usize,
            &Self::SEED,
        );
        assert_eq!(bloom.number_of_hash_functions(), Self::K_NUM);

        Self(bloom)
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Self {
        let bytes = zstd::bulk::decompress(bytes, Self::BITMAP_BYTES as usize * 2)
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
            Self::BITMAP_BYTES * 8,
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
    use pathfinder_common::felt;

    use super::*;

    const KEY: Felt = felt!("0x0218b538681900fad5a0b2ffe1d6781c0c3f14df5d32071ace0bdc9d46cb69eb");
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
}
