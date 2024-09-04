use pathfinder_common::prelude::*;
use pathfinder_crypto::Felt;

/// Converts a U256 integer to a BlockNumber
pub(crate) fn get_block_number(block_number: alloy::primitives::I256) -> BlockNumber {
    BlockNumber::new_or_panic(block_number.as_u64())
}

/// Converts an `alloy` block hash to a `pathfinder` block hash
pub(crate) fn get_block_hash(block_hash: alloy::primitives::BlockHash) -> BlockHash {
    let bytes: [u8; 32] = block_hash.into();
    BlockHash(bytes.into())
}

/// Converts an `alloy` B256 to a `pathfinder` StateCommitment
pub(crate) fn get_state_root(state_root: alloy::primitives::Uint<256, 4>) -> StateCommitment {
    let bytes: [u8; 32] = state_root.to_be_bytes();
    StateCommitment(Felt::from(bytes))
}
