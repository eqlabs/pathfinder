use primitive_types::H256;

use crate::{L1BlockNumber, L1TransactionHash, TransactionHash};

/// An L1 -> L2 message log with the corresponding L1 and L2 tx hashes
#[derive(Debug, Clone)]
pub struct L1ToL2MessageLog {
    pub message_hash: H256,
    pub l1_block_number: Option<L1BlockNumber>,
    pub l1_tx_hash: Option<L1TransactionHash>,
    pub l2_tx_hash: Option<TransactionHash>,
}
