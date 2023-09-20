use crate::common::{Address, ConsensusSignature, Fin, Hash, Iteration, Merkle, Patricia};
use crate::state::{Classes, StateDiff};
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::Signatures")]
pub struct Signatures {
    pub block_number: u64,
    pub signatures: Vec<ConsensusSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockHeader")]
pub struct BlockHeader {
    pub parent_header: Hash,
    pub number: u64,
    pub time: SystemTime,
    pub sequencer_address: Address,
    pub state_diffs: Merkle,
    pub state: Patricia,
    pub proof_fact: Hash,
    pub transactions: Merkle,
    pub events: Merkle,
    pub receipts: Merkle,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewBlock {
    BlockNumber(u64),
    Header(BlockHeadersResponse),
    Body(BlockBodiesResponse),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::BlockHeadersRequest")]
pub struct BlockHeadersRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockHeadersResponse")]
pub struct BlockHeadersResponse {
    pub block_number: u64,
    pub header_message: BlockHeaderMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockHeaderMessage {
    Header(Box<BlockHeader>),
    Signatures(Signatures),
    Fin(Fin),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::BlockBodiesRequest
")]
pub struct BlockBodiesRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockBodiesResponse")]
pub struct BlockBodiesResponse {
    pub block_number: u64,
    pub body_message: BlockBodyMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockBodyMessage {
    Diff(StateDiff),
    Classes(Classes),
    Proof(BlockProof),
    Fin(Fin),
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

impl BlockHeaderMessage {
    pub fn into_header(self) -> Option<BlockHeader> {
        match self {
            Self::Header(header) => Some(*header),
            _ => None,
        }
    }

    pub fn into_signatures(self) -> Option<Signatures> {
        match self {
            Self::Signatures(signatures) => Some(signatures),
            _ => None,
        }
    }

    pub fn into_fin(self) -> Option<Fin> {
        match self {
            Self::Fin(fin) => Some(fin),
            _ => None,
        }
    }
}

impl BlockBodyMessage {
    pub fn into_state_diff(self) -> Option<StateDiff> {
        match self {
            Self::Diff(diff) => Some(diff),
            _ => None,
        }
    }

    pub fn into_classes(self) -> Option<Classes> {
        match self {
            Self::Classes(classes) => Some(classes),
            _ => None,
        }
    }

    pub fn into_proof(self) -> Option<BlockProof> {
        match self {
            Self::Proof(proof) => Some(proof),
            _ => None,
        }
    }

    pub fn into_fin(self) -> Option<Fin> {
        match self {
            Self::Fin(fin) => Some(fin),
            _ => None,
        }
    }
}

impl ToProtobuf<proto::block::block_headers_response::HeaderMessage> for BlockHeaderMessage {
    fn to_protobuf(self) -> proto::block::block_headers_response::HeaderMessage {
        use proto::block::block_headers_response::HeaderMessage::{Fin, Header, Signatures};
        match self {
            Self::Header(header) => Header(header.to_protobuf()),
            Self::Signatures(signatures) => Signatures(signatures.to_protobuf()),
            Self::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::block::block_headers_response::HeaderMessage> for BlockHeaderMessage {
    fn try_from_protobuf(
        input: proto::block::block_headers_response::HeaderMessage,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::block::block_headers_response::HeaderMessage::{Fin, Header, Signatures};
        Ok(match input {
            Header(header) => Self::Header(Box::new(BlockHeader::try_from_protobuf(
                header, field_name,
            )?)),
            Signatures(signatures) => {
                Self::Signatures(self::Signatures::try_from_protobuf(signatures, field_name)?)
            }
            Fin(fin) => Self::Fin(self::Fin::try_from_protobuf(fin, field_name)?),
        })
    }
}

impl ToProtobuf<proto::block::block_bodies_response::BodyMessage> for BlockBodyMessage {
    fn to_protobuf(self) -> proto::block::block_bodies_response::BodyMessage {
        use proto::block::block_bodies_response::BodyMessage::{Classes, Diff, Fin, Proof};
        match self {
            Self::Diff(header) => Diff(header.to_protobuf()),
            Self::Classes(signatures) => Classes(signatures.to_protobuf()),
            Self::Proof(proof) => Proof(proof.to_protobuf()),
            Self::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::block::block_bodies_response::BodyMessage> for BlockBodyMessage {
    fn try_from_protobuf(
        input: proto::block::block_bodies_response::BodyMessage,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::block::block_bodies_response::BodyMessage::{Classes, Diff, Fin, Proof};
        Ok(match input {
            Diff(header) => Self::Diff(StateDiff::try_from_protobuf(header, field_name)?),
            Classes(signatures) => {
                Self::Classes(self::Classes::try_from_protobuf(signatures, field_name)?)
            }
            Proof(proof) => Self::Proof(BlockProof::try_from_protobuf(proof, field_name)?),
            Fin(fin) => Self::Fin(self::Fin::try_from_protobuf(fin, field_name)?),
        })
    }
}
