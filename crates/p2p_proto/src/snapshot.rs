use crate::common::Hash;
use crate::{proto, ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use stark_hash::Felt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Dummy)]
pub enum PatriciaNode {
    Binary {
        left: Felt,
        right: Felt,
    },
    Edge {
        length: u32,
        path: Felt,
        value: Felt,
    },
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
                format!("Missing {field_name} in PatriciaNode"),
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
#[protobuf(name = "crate::proto::snapshot::GetContractRange")]
pub struct GetContractRange {
    pub root: Hash,
    pub start: Hash,
    pub end: Hash,
    pub chunks_per_proof: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractRange")]
pub struct ContractRange {
    pub state: Vec<ContractState>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::GetClassRange")]
pub struct GetClassRange {
    pub root: Hash,
    pub start: Hash,
    pub end: Hash,
    pub chunks_per_proof: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::StorageLeafQuery")]
pub struct StorageLeafQuery {
    pub root: Hash,
    pub key: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::StorageRangeQuery")]
pub struct StorageRangeQuery {
    pub range_id: u32,
    pub start: StorageLeafQuery,
    pub end: StorageLeafQuery,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::GetContractStorageRange")]
pub struct GetContractStorageRange {
    pub state_root: Hash,
    pub query: Vec<StorageRangeQuery>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf)]
#[protobuf(name = "crate::proto::snapshot::ContractStorageRange")]
pub struct ContractStorageRange {
    pub range_id: u32,
    pub root: Hash,
}
