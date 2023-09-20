use std::fmt::Debug;

use crate::common::{Address, Hash};
use crate::{ToProtobuf, TryFromProtobuf};
use fake::Dummy;
use stark_hash::Felt;

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::ContractStoredValue")]
pub struct ContractStoredValue {
    pub key: Felt,
    pub value: Felt,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::state_diff::ContractDiff")]
pub struct ContractDiff {
    pub address: Address,
    #[optional]
    pub nonce: Option<Felt>,
    #[optional]
    pub class_hash: Option<Felt>,
    pub values: Vec<ContractStoredValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::StateDiff")]
pub struct StateDiff {
    pub domain: u32,
    pub contract_diffs: Vec<ContractDiff>,
}

#[derive(Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::Class")]
pub struct Class {
    pub compiled_hash: Hash,
    pub definition: Vec<u8>,
    #[optional]
    pub total_parts: Option<u32>,
    #[optional]
    pub part_num: Option<u32>,
}

impl Debug for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Class")
            .field("compiled_hash", &self.compiled_hash)
            .field("definition.len", &self.definition.len())
            .field("total_parts", &self.total_parts)
            .field("part_num", &self.part_num)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ToProtobuf, TryFromProtobuf, Dummy)]
#[protobuf(name = "crate::proto::state::Classes")]
pub struct Classes {
    pub domain: u32,
    pub classes: Vec<Class>,
}
