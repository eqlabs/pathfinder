use std::fmt::Debug;

use fake::Dummy;
use pathfinder_crypto::Felt;
use tagged::Tagged;
use tagged_debug_derive::TaggedDebug;

use crate::common::{Address, Hash, Iteration, VolitionDomain};
use crate::{proto, proto_field, ToProtobuf, TryFromProtobuf};

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::ContractStoredValue")]
pub struct ContractStoredValue {
    pub key: Felt,
    pub value: Felt,
}

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, TaggedDebug)]
#[protobuf(name = "crate::proto::state::ContractDiff")]
pub struct ContractDiff {
    pub address: Address,
    #[optional]
    pub nonce: Option<Felt>,
    #[optional]
    pub class_hash: Option<Hash>,
    pub values: Vec<ContractStoredValue>,
    pub domain: VolitionDomain,
}

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy, TaggedDebug)]
#[protobuf(name = "crate::proto::state::DeclaredClass")]
pub struct DeclaredClass {
    pub class_hash: Hash,
    // Present only if the class is Cairo1
    #[optional]
    pub compiled_class_hash: Option<Hash>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::StateDiffsRequest")]
pub struct StateDiffsRequest {
    pub iteration: Iteration,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Dummy)]
pub enum StateDiffsResponse {
    ContractDiff(ContractDiff),
    DeclaredClass(DeclaredClass),
    #[default]
    Fin,
}

impl ToProtobuf<proto::state::StateDiffsResponse> for StateDiffsResponse {
    fn to_protobuf(self) -> proto::state::StateDiffsResponse {
        use proto::state::state_diffs_response::StateDiffMessage::{
            ContractDiff, DeclaredClass, Fin,
        };
        proto::state::StateDiffsResponse {
            state_diff_message: Some(match self {
                Self::ContractDiff(contract_diff) => ContractDiff(contract_diff.to_protobuf()),
                Self::DeclaredClass(declared_class) => DeclaredClass(declared_class.to_protobuf()),
                Self::Fin => Fin(proto::common::Fin {}),
            }),
        }
    }
}

impl TryFromProtobuf<proto::state::StateDiffsResponse> for StateDiffsResponse {
    fn try_from_protobuf(
        input: proto::state::StateDiffsResponse,
        field_name: &'static str,
    ) -> Result<Self, std::io::Error> {
        use proto::state::state_diffs_response::StateDiffMessage::{
            ContractDiff, DeclaredClass, Fin,
        };
        match proto_field(input.state_diff_message, field_name)? {
            ContractDiff(x) => {
                TryFromProtobuf::try_from_protobuf(x, field_name).map(Self::ContractDiff)
            }
            DeclaredClass(x) => {
                TryFromProtobuf::try_from_protobuf(x, field_name).map(Self::DeclaredClass)
            }
            Fin(_) => Ok(Self::Fin),
        }
    }
}
