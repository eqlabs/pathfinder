use stark_hash::StarkHash;

use super::proto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub parent_block_hash: StarkHash,
    pub block_number: u64,
    pub global_state_root: StarkHash,
    pub sequencer_address: StarkHash,
    pub block_timestamp: u64,

    pub transaction_count: u32,
    pub transaction_commitment: StarkHash,

    pub event_count: u32,
    pub event_commitment: StarkHash,

    pub protocol_version: u32,
}

impl TryFrom<proto::common::BlockHeader> for BlockHeader {
    type Error = std::io::Error;

    fn try_from(block: proto::common::BlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            parent_block_hash: block
                .parent_block_hash
                .ok_or_else(|| invalid_data("Missing parent_block_hash"))?
                .try_into()?,
            block_number: block.block_number,
            global_state_root: block
                .global_state_root
                .ok_or_else(|| invalid_data("Missing global_state_root"))?
                .try_into()?,
            sequencer_address: block
                .sequencer_address
                .ok_or_else(|| invalid_data("Missing sequencer_address"))?
                .try_into()?,
            block_timestamp: block.block_timestamp,
            transaction_count: block.transaction_count,
            transaction_commitment: block
                .transaction_commitment
                .ok_or_else(|| invalid_data("Missing transaction_commitment"))?
                .try_into()?,
            event_count: block.event_count,
            event_commitment: block
                .event_commitment
                .ok_or_else(|| invalid_data("Missing event_commitment"))?
                .try_into()?,
            protocol_version: block.protocol_version,
        })
    }
}

impl From<BlockHeader> for proto::common::BlockHeader {
    fn from(block: BlockHeader) -> Self {
        Self {
            parent_block_hash: Some(block.parent_block_hash.into()),
            block_number: block.block_number,
            global_state_root: Some(block.global_state_root.into()),
            sequencer_address: Some(block.sequencer_address.into()),
            block_timestamp: block.block_timestamp,
            transaction_count: block.transaction_count,
            transaction_commitment: Some(block.transaction_commitment.into()),
            event_count: block.event_count,
            event_commitment: Some(block.event_commitment.into()),
            protocol_version: block.protocol_version,
        }
    }
}

fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}
