use primitive_types::H256;

/// An L1 -> L2 message hash with the L1 tx hash where it was sent
#[derive(Debug, Clone)]
pub struct L1ToL2MessageLog {
    pub message_hash: H256,
    pub l1_tx_hash: H256,
}
