use crate::common::{Fin, Hash};
use crate::state::Classes;
use crate::state::ContractStoredValue;
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use stark_hash::Felt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub enum PatriciaNode {
    Edge {
        length: u32,
        path: Felt,
        value: Felt,
    },
    Binary {
        left: Felt,
        right: Felt,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::PatriciaRangeProof")]
pub struct PatriciaRangeProof {
    pub nodes: Vec<PatriciaNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractState")]
pub struct ContractState {
    pub address: Hash,
    pub class: Hash,
    pub storage: Hash,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractRangeRequest")]
pub struct ContractRangeRequest {
    pub domain: u32,
    pub state_root: Hash,
    pub start: Hash,
    pub end: Hash,
    pub chunks_per_proof: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractRange")]
pub struct ContractRange {
    pub state: Vec<ContractState>,
}

// message ContractRangeResponse {
//     starknet.common.Hash state_root     = 1;
//     starknet.common.Hash contracts_root = 2;
//     starknet.common.Hash classes_root   = 3;
//     oneof responses {
//         ContractRange       range = 4;
//         starknet.common.Fin fin   = 5;
//     }
// }

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractRangeResponse")]
pub struct ContractRangeResponse {
    pub state_root: Hash,
    pub contracts_root: Hash,
    pub classes_root: Hash,
    #[rename(responses)]
    pub kind: ContractRangeResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractRangeResponseKind {
    Range(ContractRange),
    Fin(Fin),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ClassRangeRequest")]
pub struct ClassRangeRequest {
    pub root: Hash,
    pub start: Hash,
    pub end: Hash,
    pub chunks_per_proof: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ClassRangeResponse")]
struct ClassRangeResponse {
    pub root: Hash,
    pub contracts_root: Hash,
    pub classes_root: Hash,
    #[rename(responses)]
    pub kind: ClassRangeResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassRangeResponseKind {
    Classes(Classes),
    Fin(Fin),
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::StorageLeafQuery")]
pub struct StorageLeafQuery {
    pub contract_storage_root: Hash,
    pub key: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::StorageRangeQuery")]
pub struct StorageRangeQuery {
    pub start: StorageLeafQuery,
    pub end: StorageLeafQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractStorageRequest")]
pub struct ContractStorageRequest {
    pub domain: u32,
    pub state_root: Hash,
    pub query: Vec<StorageRangeQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractStorage")]
pub struct ContractStorage {
    pub key_value: Vec<ContractStoredValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractStorageResponse")]
pub struct ContractStorageResponse {
    pub state_root: Hash,
    #[rename(responses)]
    pub kind: ContractStorageResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractStorageResponseKind {
    Storage(ContractStorage),
    Fin(Fin),
}

impl ToProtobuf<proto::snapshot::PatriciaNode> for PatriciaNode {
    fn to_protobuf(self) -> proto::snapshot::PatriciaNode {
        use proto::snapshot::patricia_node::{Binary, Edge, Node};
        let node = Some(match self {
            PatriciaNode::Binary { left, right } => Node::Binary(Binary {
                left: Some(left.to_protobuf()),
                right: Some(right.to_protobuf()),
            }),
            PatriciaNode::Edge {
                length,
                path,
                value,
            } => Node::Edge(Edge {
                length,
                path: Some(path.to_protobuf()),
                value: Some(value.to_protobuf()),
            }),
        });
        proto::snapshot::PatriciaNode { node }
    }
}

impl TryFromProtobuf<proto::snapshot::PatriciaNode> for PatriciaNode {
    fn try_from_protobuf(
        input: proto::snapshot::PatriciaNode,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::snapshot::patricia_node::Node;
        let proto::snapshot::PatriciaNode { node } = input;
        let node = node.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Missing node field in {field_name}"),
            )
        })?;
        Ok(match node {
            Node::Binary(b) => PatriciaNode::Binary {
                left: TryFromProtobuf::try_from_protobuf(b.left, field_name)?,
                right: TryFromProtobuf::try_from_protobuf(b.right, field_name)?,
            },
            Node::Edge(e) => PatriciaNode::Edge {
                length: e.length,
                path: TryFromProtobuf::try_from_protobuf(e.path, field_name)?,
                value: TryFromProtobuf::try_from_protobuf(e.value, field_name)?,
            },
        })
    }
}

impl ToProtobuf<proto::snapshot::contract_range_response::Responses> for ContractRangeResponseKind {
    fn to_protobuf(self) -> proto::snapshot::contract_range_response::Responses {
        use proto::snapshot::contract_range_response::Responses::{Fin, Range};
        match self {
            Self::Range(range) => Range(range.to_protobuf()),
            Self::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::snapshot::contract_range_response::Responses>
    for ContractRangeResponseKind
{
    fn try_from_protobuf(
        input: proto::snapshot::contract_range_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::snapshot::contract_range_response::Responses::{Fin, Range};
        Ok(match input {
            Range(range) => Self::Range(TryFromProtobuf::try_from_protobuf(range, field_name)?),
            Fin(fin) => Self::Fin(TryFromProtobuf::try_from_protobuf(fin, field_name)?),
        })
    }
}

impl ToProtobuf<proto::snapshot::class_range_response::Responses> for ClassRangeResponseKind {
    fn to_protobuf(self) -> proto::snapshot::class_range_response::Responses {
        use proto::snapshot::class_range_response::Responses::{Classes, Fin};
        match self {
            Self::Classes(classes) => Classes(classes.to_protobuf()),
            Self::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::snapshot::class_range_response::Responses> for ClassRangeResponseKind {
    fn try_from_protobuf(
        input: proto::snapshot::class_range_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::snapshot::class_range_response::Responses::{Classes, Fin};
        Ok(match input {
            Classes(classes) => {
                Self::Classes(TryFromProtobuf::try_from_protobuf(classes, field_name)?)
            }
            Fin(fin) => Self::Fin(TryFromProtobuf::try_from_protobuf(fin, field_name)?),
        })
    }
}

impl ToProtobuf<proto::snapshot::contract_storage_response::Responses>
    for ContractStorageResponseKind
{
    fn to_protobuf(self) -> proto::snapshot::contract_storage_response::Responses {
        use proto::snapshot::contract_storage_response::Responses::{Fin, Storage};
        match self {
            Self::Storage(storage) => Storage(storage.to_protobuf()),
            Self::Fin(fin) => Fin(fin.to_protobuf()),
        }
    }
}

impl TryFromProtobuf<proto::snapshot::contract_storage_response::Responses>
    for ContractStorageResponseKind
{
    fn try_from_protobuf(
        input: proto::snapshot::contract_storage_response::Responses,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::snapshot::contract_storage_response::Responses::{Fin, Storage};
        Ok(match input {
            Storage(storage) => {
                Self::Storage(TryFromProtobuf::try_from_protobuf(storage, field_name)?)
            }
            Fin(fin) => Self::Fin(TryFromProtobuf::try_from_protobuf(fin, field_name)?),
        })
    }
}
