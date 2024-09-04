use pathfinder_common::prelude::*;
use pathfinder_crypto::Felt;

/// Converts a `Signed<256, 4>` integer to a `BlockNumber`
pub(crate) fn get_block_number(block_number: alloy::primitives::Signed<256, 4>) -> BlockNumber {
    let block_number = block_number.as_i64();
    debug_assert!(block_number >= 0, "Received negative block number");
    BlockNumber::new_or_panic(block_number as u64)
}

/// Converts an `alloy` block hash to a `pathfinder` block hash
pub(crate) fn get_block_hash(block_hash: alloy::primitives::Uint<256, 4>) -> BlockHash {
    let bytes: [u8; 32] = block_hash.to_be_bytes();
    BlockHash(bytes.into())
}

/// Converts a `Signed<256, 4>` integer to a `StateCommitment`
pub(crate) fn get_state_root(state_root: alloy::primitives::Uint<256, 4>) -> StateCommitment {
    let bytes: [u8; 32] = state_root.to_be_bytes();
    StateCommitment(Felt::from(bytes))
}
