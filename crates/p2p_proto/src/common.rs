use std::fmt::Display;

use fake::Dummy;
use libp2p_identity::PeerId;
use pathfinder_crypto::Felt;
use primitive_types::H256;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{proto, ToProtobuf, TryFromProtobuf};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Dummy,
    std::hash::Hash,
    Default,
    Serialize,
    Deserialize,
)]
pub struct Hash(pub Felt);

impl Hash {
    pub const ZERO: Self = Self(Felt::ZERO);
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, std::hash::Hash, Default)]
pub struct Hash256(pub primitive_types::H256);

impl<T> Dummy<T> for Hash256 {
    fn dummy_with_rng<R: Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        Self(H256::random_using(rng))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::Hashes")]
pub struct Hashes {
    pub items: Vec<Hash>,
}

#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Dummy, Default, Serialize, Deserialize,
)]
pub struct Address(pub Felt);

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::ConsensusSignature")]
pub struct ConsensusSignature {
    pub r: Felt,
    pub s: Felt,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, Default)]
#[protobuf(name = "crate::proto::common::Patricia")]
pub struct Patricia {
    pub n_leaves: u64,
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

#[derive(
    Debug, Default, Copy, Clone, PartialEq, Eq, Dummy, serde::Serialize, serde::Deserialize,
)]
pub enum L1DataAvailabilityMode {
    #[default]
    Calldata,
    Blob,
}

impl ToProtobuf<i32> for L1DataAvailabilityMode {
    fn to_protobuf(self) -> i32 {
        use proto::common::L1DataAvailabilityMode::{Blob, Calldata};
        match self {
            L1DataAvailabilityMode::Calldata => Calldata as i32,
            L1DataAvailabilityMode::Blob => Blob as i32,
        }
    }
}

impl TryFromProtobuf<i32> for L1DataAvailabilityMode {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use proto::common::L1DataAvailabilityMode::{Blob, Calldata};
        Ok(
            match TryFrom::try_from(input).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Invalid L1 data availability mode field element {field_name} enum value: \
                         {e}"
                    ),
                )
            })? {
                Calldata => L1DataAvailabilityMode::Calldata,
                Blob => L1DataAvailabilityMode::Blob,
            },
        )
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub enum VolitionDomain {
    L1,
    L2,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub enum BlockNumberOrHash {
    Number(u64),
    Hash(Hash),
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

impl ToProtobuf<proto::common::Hash256> for Hash256 {
    fn to_protobuf(self) -> proto::common::Hash256 {
        proto::common::Hash256 {
            elements: self.0.as_fixed_bytes().into(),
        }
    }
}

impl TryFromProtobuf<proto::common::Hash256> for Hash256 {
    fn try_from_protobuf(
        input: proto::common::Hash256,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        if input.elements.len() != H256::len_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Invalid field element {field_name}: expected to be {} bytes long",
                    H256::len_bytes()
                ),
            ));
        }
        let hash = H256::from_slice(&input.elements);
        Ok(Hash256(hash))
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

impl ToProtobuf<i32> for VolitionDomain {
    fn to_protobuf(self) -> i32 {
        use proto::common::VolitionDomain::{L1, L2};
        match self {
            VolitionDomain::L1 => L1 as i32,
            VolitionDomain::L2 => L2 as i32,
        }
    }
}

impl TryFromProtobuf<i32> for VolitionDomain {
    fn try_from_protobuf(input: i32, field_name: &'static str) -> Result<Self, std::io::Error> {
        use proto::common::VolitionDomain::{L1, L2};
        Ok(
            match TryFrom::try_from(input).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("Invalid volition domain field element {field_name} enum value: {e}"),
                )
            })? {
                L1 => VolitionDomain::L1,
                L2 => VolitionDomain::L2,
            },
        )
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

impl ToProtobuf<proto::common::Uint128> for u128 {
    fn to_protobuf(self) -> proto::common::Uint128 {
        proto::common::Uint128 {
            low: (self & 0xFFFF_FFFF_FFFF_FFFF) as u64,
            high: (self >> 64) as u64,
        }
    }
}

impl TryFromProtobuf<proto::common::Uint128> for u128 {
    fn try_from_protobuf(
        input: proto::common::Uint128,
        _: &'static str,
    ) -> Result<Self, std::io::Error> {
        Ok(((input.high as u128) << 64) | input.low as u128)
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

impl ToProtobuf<proto::sync::common::iteration::Start> for BlockNumberOrHash {
    fn to_protobuf(self) -> proto::sync::common::iteration::Start {
        use proto::sync::common::iteration::Start::{BlockNumber, Header};
        match self {
            BlockNumberOrHash::Number(number) => BlockNumber(number),
            BlockNumberOrHash::Hash(hash) => Header(hash.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::sync::common::iteration::Start> for BlockNumberOrHash {
    fn try_from_protobuf(
        input: proto::sync::common::iteration::Start,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::sync::common::iteration::Start::{BlockNumber, Header};
        Ok(match input {
            BlockNumber(number) => BlockNumberOrHash::Number(number),
            Header(hash) => BlockNumberOrHash::Hash(Hash::try_from_protobuf(hash, field_name)?),
        })
    }
}
