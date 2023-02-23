mod hash;
mod poseidon;

pub use hash::{poseidon_hash, poseidon_hash_many, PoseidonHasher};
pub use poseidon::{permute, permute_comp, PoseidonState};
