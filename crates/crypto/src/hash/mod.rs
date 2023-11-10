/// Pedersen hash function.
pub mod pedersen;

/// Poseidon hash function.
pub mod poseidon;

pub use pedersen::{pedersen_hash, HashChain};
pub use poseidon::{poseidon_hash, poseidon_hash_many, PoseidonHasher};
