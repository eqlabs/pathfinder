use crate::{stark_hash, StarkHash};

/// HashChain is the structure used over at cairo side to represent the hash construction needed
/// for computing the class hash.
///
/// Empty hash chained value equals `H(0, 0)` where `H` is the [`stark_hash()`] function, and the
/// second value is the number of values hashed together in this chain. For other values, the
/// accumulator is on each update replaced with the `H(hash, value)` and the number of count
/// incremented by one.
pub struct HashChain {
    hash: StarkHash,
    count: usize,
}

impl Default for HashChain {
    fn default() -> Self {
        HashChain {
            hash: StarkHash::ZERO,
            count: 0,
        }
    }
}

impl HashChain {
    pub fn update(&mut self, value: StarkHash) {
        self.hash = stark_hash(self.hash, value);
        self.count = self
            .count
            .checked_add(1)
            .expect("could not have deserialized larger than usize Vecs");
    }

    pub fn finalize(self) -> StarkHash {
        let count = StarkHash::from_be_slice(&self.count.to_be_bytes())
            .expect("usize is smaller than 251-bits");
        stark_hash(self.hash, count)
    }
}

#[cfg(test)]
mod tests {
    use super::{HashChain, StarkHash};

    #[test]
    fn test_non_empty_chain() {
        let mut chain = HashChain::default();

        chain.update(StarkHash::from_hex_str("0x1").unwrap());
        chain.update(StarkHash::from_hex_str("0x2").unwrap());
        chain.update(StarkHash::from_hex_str("0x3").unwrap());
        chain.update(StarkHash::from_hex_str("0x4").unwrap());

        let computed_hash = chain.finalize();

        // produced by the cairo-lang Python implementation:
        // `hex(compute_hash_on_elements([1, 2, 3, 4]))`
        let expected_hash = StarkHash::from_hex_str(
            "0x66bd4335902683054d08a0572747ea78ebd9e531536fb43125424ca9f902084",
        )
        .unwrap();

        assert_eq!(expected_hash, computed_hash);
    }
}
