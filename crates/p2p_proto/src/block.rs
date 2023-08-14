use crate::common::{Address, BlockId, ChainId, Hash, Merkle, Signature};
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::Signatures")]
pub struct Signatures {
    pub id: BlockId,
    pub signatures: Vec<Signature>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockHeader")]
pub struct BlockHeader {
    pub parent_block: BlockId,
    pub time: SystemTime, // Use the custom conversion implementation for this
    pub sequencer_address: Address,
    pub state_diffs: Merkle,
    pub state: Merkle,
    pub proof_fact: Hash,
    pub transactions: Merkle,
    pub events: Merkle,
    pub receipts: Merkle,
    pub protocol_version: u32,
    pub chain_id: ChainId,
}

impl ToProtobuf<::prost_types::Timestamp> for SystemTime {
    fn to_protobuf(self) -> ::prost_types::Timestamp {
        self.into()
    }
}

impl TryFromProtobuf<::prost_types::Timestamp> for SystemTime {
    fn try_from_protobuf(
        input: ::prost_types::Timestamp,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let secs = input.seconds.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid secs in Timestamp {field_name}: {e}"),
            )
        })?;
        let nanos = input.nanos.try_into().map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid nanos in Timestamp {field_name}: {e}"),
            )
        })?;

        Self::UNIX_EPOCH
            .checked_add(Duration::new(secs, nanos))
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Timestamp {field_name}"),
            ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockProof")]
pub struct BlockProof {
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::NewBlock")]
pub struct NewBlock {
    pub id: BlockId,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::GetBlocks")]
pub struct GetBlocks {
    pub start: BlockId,
    pub direction: Direction,
    pub limit: u64,
    pub skip: u64,
    pub step: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Dummy)]
pub enum Direction {
    Forward,
    Backward,
}

impl TryFromProtobuf<i32> for Direction {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use proto::block::get_blocks;

        let input = get_blocks::Direction::from_i32(input).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Direction {field_name}"),
            )
        })?;
        Ok(match input {
            get_blocks::Direction::Backward => Direction::Backward,
            get_blocks::Direction::Forward => Direction::Forward,
        })
    }
}

impl ToProtobuf<i32> for Direction {
    fn to_protobuf(self) -> i32 {
        use proto::block::get_blocks;

        match self {
            Direction::Forward => get_blocks::Direction::Forward as i32,
            Direction::Backward => get_blocks::Direction::Backward as i32,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::GetSignatures")]
pub struct GetSignatures {
    pub id: BlockId,
}
