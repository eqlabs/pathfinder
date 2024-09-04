use primitive_types::H256;

use crate::BlockNumber;

/// An L1 -> L2 message hash with the block and tx where it was sent
#[derive(Debug, Clone)]
pub struct L1ToL2MessageHash {
    pub message_hash: H256,
    pub l1_tx_hash: H256,
    pub l1_block_number: BlockNumber,
    pub is_finalized: bool,
}
