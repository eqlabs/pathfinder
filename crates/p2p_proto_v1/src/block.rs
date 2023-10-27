use crate::common::{Address, BlockId, ConsensusSignature, Fin, Hash, Iteration, Merkle, Patricia};
use crate::state::{Classes, StateDiff};
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::{Dummy, Fake, Faker};
use std::fmt::Display;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::Signatures")]
pub struct Signatures {
    pub block: BlockId,
    pub signatures: Vec<ConsensusSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockHeader")]
pub struct BlockHeader {
    #[rename(parent_header)]
    pub parent_hash: Hash,
    pub number: u64,
    pub time: SystemTime,
    pub sequencer_address: Address,
    pub state_diffs: Merkle,
    pub state: Patricia,
    pub proof_fact: Hash,
    pub transactions: Merkle,
    pub events: Merkle,
    pub receipts: Merkle,
    pub hash: Hash,
    pub gas_price: Vec<u8>,
    pub starknet_version: String,
    #[optional]
    pub state_commitment: Option<Hash>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::BlockProof")]
pub struct BlockProof {
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum NewBlock {
    Id(BlockId),
    Header(BlockHeadersResponse),
    Body(BlockBodiesResponse),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::BlockHeadersRequest")]
pub struct BlockHeadersRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::BlockHeadersResponse")]
pub struct BlockHeadersResponse {
    #[rename(part)]
    pub parts: Vec<BlockHeadersResponsePart>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum BlockHeadersResponsePart {
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

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::block::BlockBodiesResponse")]
pub struct BlockBodiesResponse {
    #[optional]
    pub id: Option<BlockId>,
    pub body_message: BlockBodyMessage,
}

// TODO remove when streaming response implemented
#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::block::BlockBodiesResponseList")]
pub struct BlockBodiesResponseList {
    pub items: Vec<BlockBodiesResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
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

impl<T> Dummy<T> for BlockHeader {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self {
            time: SystemTime::now(),
            parent_hash: Faker.fake_with_rng(rng),
            number: Faker.fake_with_rng(rng),
            sequencer_address: Faker.fake_with_rng(rng),
            state_diffs: Faker.fake_with_rng(rng),
            state: Faker.fake_with_rng(rng),
            proof_fact: Faker.fake_with_rng(rng),
            transactions: Faker.fake_with_rng(rng),
            events: Faker.fake_with_rng(rng),
            receipts: Faker.fake_with_rng(rng),
            hash: Faker.fake_with_rng(rng),
            gas_price: Faker.fake_with_rng(rng),
            starknet_version: Faker.fake_with_rng(rng),
            state_commitment: Faker.fake_with_rng(rng),
        }
    }
}

impl ToProtobuf<crate::proto::block::NewBlock> for NewBlock {
    fn to_protobuf(self) -> crate::proto::block::NewBlock {
        use crate::proto::block::new_block::MaybeFull::{Body, Header, Id};
        crate::proto::block::NewBlock {
            maybe_full: Some(match self {
                Self::Id(block_number) => Id(block_number.to_protobuf()),
                Self::Header(header) => Header(header.to_protobuf()),
                Self::Body(body) => Body(body.to_protobuf()),
            }),
        }
    }
}

impl TryFromProtobuf<crate::proto::block::NewBlock> for NewBlock {
    fn try_from_protobuf(
        input: crate::proto::block::NewBlock,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use crate::proto::block::new_block::MaybeFull::{Body, Header, Id};
        let x = input.maybe_full.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to parse {field_name}: missing maybe_full field"),
            )
        })?;

        Ok(match x {
            Id(i) => Self::Id(TryFromProtobuf::try_from_protobuf(i, field_name)?),
            Header(h) => Self::Header(TryFromProtobuf::try_from_protobuf(h, field_name)?),
            Body(b) => Self::Body(TryFromProtobuf::try_from_protobuf(b, field_name)?),
        })
    }
}

impl BlockHeadersResponse {
    pub fn into_fin(self) -> Option<Fin> {
        if self.parts.len() == 1 {
            let mut parts = self.parts;
            parts.pop().unwrap().into_fin()
        } else {
            None
        }
    }
}

impl Display for BlockHeadersResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockHeadersResponse[")?;
        if self.parts.len() == 1 {
            write!(f, "{}", self.parts[0])?;
        } else if self.parts.len() > 1 {
            write!(
                f,
                "{},..,{}",
                self.parts.first().unwrap(),
                self.parts.last().unwrap()
            )?;
        }
        write!(f, "]")
    }
}

impl From<Fin> for BlockHeadersResponsePart {
    fn from(fin: Fin) -> Self {
        Self::Fin(fin)
    }
}

impl BlockHeadersResponsePart {
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

    pub fn id(&self) -> Option<BlockId> {
        match self {
            Self::Header(header) => Some(BlockId {
                hash: header.hash,
                number: header.number,
            }),
            Self::Signatures(signatures) => Some(signatures.block),
            Self::Fin(_) => None,
        }
    }
}

impl Display for BlockHeadersResponsePart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(header) => write!(f, "({},{})", header.number, header.hash.0),
            Self::Signatures(signatures) => write!(f, "{}", signatures.block),
            Self::Fin(_) => write!(f, "Fin"),
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

impl ToProtobuf<proto::block::BlockHeadersResponsePart> for BlockHeadersResponsePart {
    fn to_protobuf(self) -> proto::block::BlockHeadersResponsePart {
        use proto::block::block_headers_response_part::HeaderMessage::{Fin, Header, Signatures};
        proto::block::BlockHeadersResponsePart {
            header_message: Some(match self {
                Self::Header(header) => Header(header.to_protobuf()),
                Self::Signatures(signatures) => Signatures(signatures.to_protobuf()),
                Self::Fin(fin) => Fin(fin.to_protobuf()),
            }),
        }
    }
}

impl TryFromProtobuf<proto::block::BlockHeadersResponsePart> for BlockHeadersResponsePart {
    fn try_from_protobuf(
        input: proto::block::BlockHeadersResponsePart,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::block::block_headers_response_part::HeaderMessage::{Fin, Header, Signatures};
        Ok(match input.header_message {
            Some(Header(header)) => Self::Header(Box::new(BlockHeader::try_from_protobuf(
                header, field_name,
            )?)),
            Some(Signatures(signatures)) => {
                Self::Signatures(self::Signatures::try_from_protobuf(signatures, field_name)?)
            }
            Some(Fin(fin)) => Self::Fin(self::Fin::try_from_protobuf(fin, field_name)?),
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Failed to parse {field_name}: missing header_message field"),
                ))
            }
        })
    }
}

impl From<Fin> for BlockBodiesResponse {
    fn from(fin: Fin) -> Self {
        Self {
            id: None,
            body_message: BlockBodyMessage::Fin(fin),
        }
    }
}

impl BlockBodiesResponse {
    pub fn into_fin(self) -> Option<Fin> {
        self.body_message.into_fin()
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

impl Display for BlockBodiesResponseList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockBodiesResponseList[")?;
        if self.items.len() == 1 {
            if let Some(id) = self.items[0].id {
                id.fmt(f)?
            } else {
                write!(f, "...")?
            }
        } else if self.items.len() > 1 {
            match (
                self.items.first().unwrap().id,
                self.items.last().unwrap().id,
            ) {
                (Some(a), Some(b)) => write!(f, "{a},..,{b}")?,
                _ => write!(f, "...")?,
            }
        }
        write!(f, "]")
    }
}
