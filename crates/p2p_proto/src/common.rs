use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use libp2p_identity::PeerId;
use pathfinder_crypto::Felt;
use rand::Rng;
use std::{fmt::Display, num::NonZeroU64};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy, std::hash::Hash, Default)]
pub struct Hash(pub Felt);

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::Hashes")]
pub struct Hashes {
    pub items: Vec<Hash>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy, Default)]
pub struct Address(pub Felt);

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::ConsensusSignature")]
pub struct ConsensusSignature {
    pub r: Felt,
    pub s: Felt,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, Default)]
#[protobuf(name = "crate::proto::common::Merkle")]
pub struct Merkle {
    pub n_leaves: u32,
    pub root: Hash,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, Default)]
#[protobuf(name = "crate::proto::common::Patricia")]
pub struct Patricia {
    pub height: u32,
    pub root: Hash,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, std::hash::Hash,
)]
#[protobuf(name = "crate::proto::common::BlockId")]
pub struct BlockId {
    pub number: u64,
    #[rename(header)]
    pub hash: Hash,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::Iteration")]
pub struct Iteration {
    pub start: BlockNumberOrHash,
    pub direction: Direction,
    pub limit: u64,
    pub step: Step,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub enum BlockNumberOrHash {
    Number(u64),
    Hash(Hash),
}

/// Guaranteed to always be `>= 1`, defaults to `1` if constructed from `None` or `Some(0)`
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Step(NonZeroU64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Dummy)]
pub enum Direction {
    Forward,
    Backward,
}

impl ToProtobuf<proto::common::Felt252> for Felt {
    fn to_protobuf(self) -> proto::common::Felt252 {
        proto::common::Felt252 {
            elements: self.to_be_bytes().into(),
        }
    }
}

impl TryFromProtobuf<proto::common::Felt252> for Felt {
    fn try_from_protobuf(
        input: proto::common::Felt252,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let stark_hash = Felt::from_be_slice(&input.elements).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field element {field_name}: {e}"),
            )
        })?;
        Ok(stark_hash)
    }
}

impl ToProtobuf<proto::common::Hash> for Hash {
    fn to_protobuf(self) -> proto::common::Hash {
        proto::common::Hash {
            elements: self.0.to_be_bytes().into(),
        }
    }
}

impl TryFromProtobuf<proto::common::Hash> for Hash {
    fn try_from_protobuf(
        input: proto::common::Hash,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let stark_hash = Felt::from_be_slice(&input.elements).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field element {field_name}: {e}"),
            )
        })?;
        Ok(Hash(stark_hash))
    }
}

impl ToProtobuf<proto::common::Address> for Address {
    fn to_protobuf(self) -> proto::common::Address {
        proto::common::Address {
            elements: self.0.to_be_bytes().into(),
        }
    }
}

impl TryFromProtobuf<proto::common::Address> for Address {
    fn try_from_protobuf(
        input: proto::common::Address,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let stark_hash = Felt::from_be_slice(&input.elements).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field element {field_name}: {e}"),
            )
        })?;
        if stark_hash.has_more_than_251_bits() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Address {field_name} cannot have more than 251 bits"),
            ));
        }
        Ok(Address(stark_hash))
    }
}

impl Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({},{})", self.number, self.hash.0)
    }
}

impl ToProtobuf<proto::common::PeerId> for PeerId {
    fn to_protobuf(self) -> proto::common::PeerId {
        proto::common::PeerId {
            id: self.to_bytes(),
        }
    }
}

impl TryFromProtobuf<proto::common::PeerId> for PeerId {
    fn try_from_protobuf(
        input: proto::common::PeerId,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let peer_id = PeerId::from_bytes(&input.id).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid peer id {field_name}: {e}"),
            )
        })?;
        Ok(peer_id)
    }
}

impl From<u64> for BlockNumberOrHash {
    fn from(x: u64) -> Self {
        Self::Number(x)
    }
}

impl From<Felt> for BlockNumberOrHash {
    fn from(x: Felt) -> Self {
        Self::Hash(Hash(x))
    }
}

impl ToProtobuf<proto::common::iteration::Start> for BlockNumberOrHash {
    fn to_protobuf(self) -> proto::common::iteration::Start {
        use proto::common::iteration::Start::{BlockNumber, Header};
        match self {
            BlockNumberOrHash::Number(number) => BlockNumber(number),
            BlockNumberOrHash::Hash(hash) => Header(hash.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::common::iteration::Start> for BlockNumberOrHash {
    fn try_from_protobuf(
        input: proto::common::iteration::Start,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::common::iteration::Start::{BlockNumber, Header};
        Ok(match input {
            BlockNumber(number) => BlockNumberOrHash::Number(number),
            Header(hash) => BlockNumberOrHash::Hash(Hash::try_from_protobuf(hash, field_name)?),
        })
    }
}

impl Step {
    pub fn into_inner(self) -> u64 {
        self.0.get()
    }
}

impl From<u64> for Step {
    fn from(input: u64) -> Self {
        Self(NonZeroU64::new(input).unwrap_or(NonZeroU64::MIN))
    }
}

impl From<Option<u64>> for Step {
    fn from(input: Option<u64>) -> Self {
        Self::from(input.unwrap_or_default())
    }
}

impl Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<T> Dummy<T> for Step {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self(rng.gen())
    }
}

impl ToProtobuf<u64> for Step {
    fn to_protobuf(self) -> u64 {
        self.into_inner()
    }
}

impl TryFromProtobuf<u64> for Step {
    fn try_from_protobuf(input: u64, _: &'static str) -> Result<Self, std::io::Error> {
        Ok(Self::from(input))
    }
}

impl ToProtobuf<i32> for Direction {
    fn to_protobuf(self) -> i32 {
        use proto::common::iteration::Direction::{Backward, Forward};
        match self {
            Direction::Forward => Forward as i32,
            Direction::Backward => Backward as i32,
        }
    }
}

impl TryFromProtobuf<i32> for Direction {
    fn try_from_protobuf(input: i32, _: &'static str) -> Result<Self, std::io::Error> {
        use proto::common::iteration::Direction::{Backward, Forward};
        Ok(match TryFrom::try_from(input)? {
            Backward => Direction::Backward,
            Forward => Direction::Forward,
        })
    }
}
