use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use libp2p_identity::PeerId;
use stark_hash::Felt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub struct Hash(pub Felt);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub struct Address(pub Felt);

// Avoid pathfinder_common dependency
#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub struct ChainId(pub Felt);

#[derive(Debug, Clone, PartialEq, Eq, Dummy)]
pub enum BlockId {
    Hash(Hash),
    Height(u64),
    HashAndHeight(Hash, u64),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::Signature")]
pub struct Signature {
    pub parts: Vec<Felt>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::common::Merkle")]
pub struct Merkle {
    pub n_leaves: u32,
    pub root: Hash,
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

impl ToProtobuf<proto::common::ChainId> for ChainId {
    fn to_protobuf(self) -> proto::common::ChainId {
        proto::common::ChainId {
            id: self.0.to_be_bytes().into(),
        }
    }
}

impl TryFromProtobuf<proto::common::ChainId> for ChainId {
    fn try_from_protobuf(
        input: proto::common::ChainId,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        let stark_hash = Felt::from_be_slice(&input.id).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid field element {field_name}: {e}"),
            )
        })?;
        Ok(ChainId(stark_hash))
    }
}

impl ToProtobuf<proto::common::BlockId> for BlockId {
    fn to_protobuf(self) -> proto::common::BlockId {
        use proto::common::block_id::{HashAndHeight, Id};
        use proto::common::BlockId;
        let id = Some(match self {
            Self::Hash(hash) => Id::Hash(hash.to_protobuf()),
            Self::Height(height) => Id::Height(height),
            Self::HashAndHeight(hash, height) => Id::HashAndHeight(HashAndHeight {
                hash: Some(hash.to_protobuf()),
                height,
            }),
        });
        BlockId { id }
    }
}

impl TryFromProtobuf<proto::common::BlockId> for BlockId {
    fn try_from_protobuf(
        input: proto::common::BlockId,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::common::block_id::{HashAndHeight, Id};

        let id = input.id.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Empty block id {field_name}"),
            )
        })?;

        match id {
            Id::Hash(hash) => Hash::try_from_protobuf(hash, field_name).map(Self::Hash),
            Id::Height(height) => Ok(Self::Height(height)),
            Id::HashAndHeight(HashAndHeight { hash, height }) => {
                let hash = hash.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("hash missing in block id {field_name}"),
                    )
                })?;
                Hash::try_from_protobuf(hash, field_name)
                    .map(|hash| Self::HashAndHeight(hash, height))
            }
        }
    }
}
