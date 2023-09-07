use crate::common::{Address, BlockId, ChainId, Hash, Merkle, Signature};
use crate::state::{Classes, StateDiff};
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use rand::Rng;
use std::fmt::Display;
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
    pub parent_block: Hash,
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
    // FIXME extra fields added to make sync work
    pub block_hash: Hash,
    pub gas_price: Vec<u8>,
    pub starknet_version: String,
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
#[protobuf(name = "crate::proto::block::GetSignatures")]
pub struct GetSignatures {
    pub id: BlockId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Dummy)]
pub enum Direction {
    Forward,
    Backward,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::Iteration")]
pub struct Iteration {
    pub start: BlockId,
    pub direction: Direction,
    pub limit: u64,
    pub step: Step,
}

/// Guaranteed to always be `>= 1`, defaults to `1` if constructed from `None` or `Some(0)`
///
/// FIXME next spec iteration requires to return error when step is explicitly set to 0 by the requesting party
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Step(u64);

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::GetBlockHeaders")]
pub struct GetBlockHeaders {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockHeadersResponse")]
pub struct BlockHeadersResponse {
    pub id: BlockId,
    pub block_part: BlockHeadersResponsePart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockHeadersResponsePart {
    Header(Box<BlockHeader>),
    Signatures(Signatures),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::GetBlockBodies")]
pub struct GetBlockBodies {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockBodiesResponse")]
pub struct BlockBodiesResponse {
    pub id: BlockId,
    pub block_part: BlockBodiesResponsePart,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockBodiesResponsePart {
    Diff(StateDiff),
    Classes(Classes),
    Proof(BlockProof),
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

impl ToProtobuf<i32> for Direction {
    fn to_protobuf(self) -> i32 {
        use proto::block::iteration::Direction::{Backward, Forward};
        match self {
            Direction::Forward => Forward as i32,
            Direction::Backward => Backward as i32,
        }
    }
}

impl TryFromProtobuf<i32> for Direction {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use proto::block::iteration::{
            self,
            Direction::{Backward, Forward},
        };
        let input = iteration::Direction::from_i32(input).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Direction {field_name}"),
            )
        })?;
        Ok(match input {
            Backward => Direction::Backward,
            Forward => Direction::Forward,
        })
    }
}

impl Step {
    pub fn take_inner(self) -> u64 {
        self.0
    }
}

impl From<u64> for Step {
    fn from(input: u64) -> Self {
        // step 0 means the step field was actually missing or
        // the client does not know what it's actually doing :P
        let step = if input == 0 { 1 } else { input };
        Self(step)
    }
}

impl From<Option<u64>> for Step {
    fn from(input: Option<u64>) -> Self {
        Self::from(input.unwrap_or(1))
    }
}

impl Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> Dummy<T> for Step {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self(rng.gen_range(1u64..=u64::MAX))
    }
}

impl ToProtobuf<Option<u64>> for Step {
    fn to_protobuf(self) -> Option<u64> {
        Some(self.0)
    }
}

impl TryFromProtobuf<Option<u64>> for Step {
    fn try_from_protobuf(input: Option<u64>, _: &'static str) -> Result<Self, std::io::Error> {
        Ok(Self::from(input))
    }
}

impl ToProtobuf<proto::block::block_headers_response::BlockPart> for BlockHeadersResponsePart {
    fn to_protobuf(self) -> proto::block::block_headers_response::BlockPart {
        use proto::block::block_headers_response::BlockPart::{Header, Signatures};
        match self {
            Self::Header(header) => Header(header.to_protobuf()),
            Self::Signatures(signatures) => Signatures(signatures.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::block::block_headers_response::BlockPart> for BlockHeadersResponsePart {
    fn try_from_protobuf(
        input: proto::block::block_headers_response::BlockPart,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::block::block_headers_response::BlockPart::{Header, Signatures};
        Ok(match input {
            Header(header) => Self::Header(Box::new(BlockHeader::try_from_protobuf(
                header, field_name,
            )?)),
            Signatures(signatures) => {
                Self::Signatures(self::Signatures::try_from_protobuf(signatures, field_name)?)
            }
        })
    }
}

impl ToProtobuf<proto::block::block_bodies_response::BlockPart> for BlockBodiesResponsePart {
    fn to_protobuf(self) -> proto::block::block_bodies_response::BlockPart {
        use proto::block::block_bodies_response::BlockPart::{Classes, Diff, Proof};
        match self {
            Self::Diff(header) => Diff(header.to_protobuf()),
            Self::Classes(signatures) => Classes(signatures.to_protobuf()),
            Self::Proof(proof) => Proof(proof.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::block::block_bodies_response::BlockPart> for BlockBodiesResponsePart {
    fn try_from_protobuf(
        input: proto::block::block_bodies_response::BlockPart,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::block::block_bodies_response::BlockPart::{Classes, Diff, Proof};
        Ok(match input {
            Diff(header) => Self::Diff(StateDiff::try_from_protobuf(header, field_name)?),
            Classes(signatures) => {
                Self::Classes(self::Classes::try_from_protobuf(signatures, field_name)?)
            }
            Proof(proof) => Self::Proof(BlockProof::try_from_protobuf(proof, field_name)?),
        })
    }
}
