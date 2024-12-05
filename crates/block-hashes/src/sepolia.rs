use pathfinder_common::{BlockHash, BlockNumber};
use pathfinder_crypto::Felt;

const FIRST_0_13_2_BLOCK: usize = 86311;
static BLOCK_HASHES: &[u8; 32 * FIRST_0_13_2_BLOCK] =
    include_bytes!("../fixtures/sepolia_block_hashes.bin");

pub(super) fn block_hash(block_number: BlockNumber) -> Option<BlockHash> {
    if block_number.get() >= FIRST_0_13_2_BLOCK as u64 {
        None
    } else {
        let offset = (block_number.get() as usize) * 32;
        let felt = Felt::from_be_slice(&BLOCK_HASHES[offset..offset + 32]).unwrap();
        Some(BlockHash(felt))
    }
}
