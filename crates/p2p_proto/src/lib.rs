use anyhow::anyhow;
use stark_hash::StarkHash;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/starknet.rs"));
}

impl TryFrom<proto::FieldElement> for StarkHash {
    type Error = stark_hash::OverflowError;

    fn try_from(element: proto::FieldElement) -> Result<Self, Self::Error> {
        let stark_hash = StarkHash::from_be_slice(&element.elements)?;
        Ok(stark_hash)
    }
}

impl From<StarkHash> for proto::FieldElement {
    fn from(hash: StarkHash) -> Self {
        Self {
            elements: hash.to_be_bytes().into(),
        }
    }
}

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

impl TryFrom<proto::BlockHeader> for BlockHeader {
    type Error = anyhow::Error;

    fn try_from(block: proto::BlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            parent_block_hash: block
                .parent_block_hash
                .ok_or_else(|| anyhow!("Missing parent_block_hash"))?
                .try_into()?,
            block_number: block.block_number,
            global_state_root: block
                .global_state_root
                .ok_or_else(|| anyhow!("Missing global_state_root"))?
                .try_into()?,
            sequencer_address: block
                .sequencer_address
                .ok_or_else(|| anyhow!("Missing sequencer_address"))?
                .try_into()?,
            block_timestamp: block.block_timestamp,
            transaction_count: block.transaction_count,
            transaction_commitment: block
                .transaction_commitment
                .ok_or_else(|| anyhow!("Missing transaction_commitment"))?
                .try_into()?,
            event_count: block.event_count,
            event_commitment: block
                .event_commitment
                .ok_or_else(|| anyhow!("Missing event_commitment"))?
                .try_into()?,
            protocol_version: block.protocol_version,
        })
    }
}

impl From<BlockHeader> for proto::BlockHeader {
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
