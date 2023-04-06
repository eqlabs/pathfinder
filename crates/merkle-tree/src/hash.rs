//! Contains the [Hash] trait and implementations thereof for the [Pedersen](PedersenHash) and [Poseidon](PoseidonHash) hashes.

use stark_hash::Felt;

/// Hashing function used by a particular merkle tree implementation.
pub trait Hash {
    fn hash(a: Felt, b: Felt) -> Felt;
}

/// Implements [Hash] for the [StarkNet Pedersen hash](stark_hash::stark_hash).
#[derive(Debug, Clone, Copy)]
pub struct PedersenHash {}

impl Hash for PedersenHash {
    fn hash(a: Felt, b: Felt) -> Felt {
        stark_hash::stark_hash(a, b)
    }
}

/// Implements [Hash] for the [StarkNet Poseidon hash](stark_poseidon::poseidon_hash).
pub struct PoseidonHash;
impl crate::Hash for PoseidonHash {
    fn hash(a: Felt, b: Felt) -> Felt {
        stark_poseidon::poseidon_hash(a.into(), b.into()).into()
    }
}
