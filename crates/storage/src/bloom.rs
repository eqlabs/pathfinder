use bloomfilter::Bloom;
use pathfinder_crypto::Felt;

#[derive(Clone)]
pub(crate) struct BloomFilter(Bloom<Felt>);

impl BloomFilter {
    const BITMAP_BYTES: u64 = 2048;
    const ITEMS_COUNT: u32 = 1024;
    const K_NUM: u32 = 12;
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

    pub fn from_bytes(bytes: &[u8]) -> Self {
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

    pub fn as_compressed_bytes(&self) -> Vec<u8> {
        let bytes = self.as_bytes();
        let bytes = zstd::bulk::compress(&bytes, 0).expect("Compressing Bloom filter");
        bytes
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.bitmap()
    }

    pub fn set(&mut self, key: &Felt) {
        self.0.set(key);
    }

    pub fn check(&self, key: &Felt) -> bool {
        self.0.check(key)
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
        assert!(bloom.check(&KEY_NOT_IN_FILTER) == false);
    }

    #[test]
    fn serialize_roundtrip() {
        let mut bloom = BloomFilter::new();
        bloom.set(&KEY);

        let bytes = bloom.as_compressed_bytes();
        let bloom = BloomFilter::from_compressed_bytes(&bytes);
        assert!(bloom.check(&KEY));
        assert!(bloom.check(&KEY_NOT_IN_FILTER) == false);
    }
}
