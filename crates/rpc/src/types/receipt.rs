use pathfinder_common::{ContractAddress, EventData, EventKey, L2ToL1MessagePayloadElem};

use crate::felt::{RpcFelt, RpcFelt251};
use crate::types::reply::BlockStatus;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct ExecutionResourcesProperties {
    pub steps: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub memory_holes: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub range_check_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub pedersen_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub poseidon_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub ec_op_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub ecdsa_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub bitwise_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub keccak_builtin_applications: u64,
    #[cfg_attr(test, serde(skip_serializing_if = "is_zero"))]
    pub segment_arena_builtin: u64,
}

impl crate::dto::SerializeForVersion for ExecutionResourcesProperties {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("steps", &self.steps)?;
        if !is_zero(&self.memory_holes) {
            serializer.serialize_field("memory_holes", &self.memory_holes)?;
        }
        if !is_zero(&self.range_check_builtin_applications) {
            serializer.serialize_field(
                "range_check_builtin_applications",
                &self.range_check_builtin_applications,
            )?;
        }
        if !is_zero(&self.pedersen_builtin_applications) {
            serializer.serialize_field(
                "pedersen_builtin_applications",
                &self.pedersen_builtin_applications,
            )?;
        }
        if !is_zero(&self.poseidon_builtin_applications) {
            serializer.serialize_field(
                "poseidon_builtin_applications",
                &self.poseidon_builtin_applications,
            )?;
        }
        if !is_zero(&self.ec_op_builtin_applications) {
            serializer.serialize_field(
                "ec_op_builtin_applications",
                &self.ec_op_builtin_applications,
            )?;
        }
        if !is_zero(&self.ecdsa_builtin_applications) {
            serializer.serialize_field(
                "ecdsa_builtin_applications",
                &self.ecdsa_builtin_applications,
            )?;
        }
        if !is_zero(&self.bitwise_builtin_applications) {
            serializer.serialize_field(
                "bitwise_builtin_applications",
                &self.bitwise_builtin_applications,
            )?;
        }
        if !is_zero(&self.keccak_builtin_applications) {
            serializer.serialize_field(
                "keccak_builtin_applications",
                &self.keccak_builtin_applications,
            )?;
        }
        if !is_zero(&self.segment_arena_builtin) {
            serializer.serialize_field("segment_arena_builtin", &self.segment_arena_builtin)?;
        }
        serializer.end()
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl From<pathfinder_common::receipt::ExecutionResources> for ExecutionResourcesProperties {
    fn from(value: pathfinder_common::receipt::ExecutionResources) -> Self {
        let pathfinder_common::receipt::ExecutionResources {
            builtins:
                pathfinder_common::receipt::BuiltinCounters {
                    // Absent from the OpenRPC spec
                    output: _,
                    pedersen: pedersen_builtin,
                    range_check: range_check_builtin,
                    ecdsa: ecdsa_builtin,
                    bitwise: bitwise_builtin,
                    ec_op: ec_op_builtin,
                    keccak: keccak_builtin,
                    poseidon: poseidon_builtin,
                    segment_arena: segment_arena_builtin,
                    ..
                },
            n_steps,
            n_memory_holes,
            ..
        } = value;

        Self {
            steps: n_steps,
            memory_holes: n_memory_holes,
            range_check_builtin_applications: range_check_builtin,
            pedersen_builtin_applications: pedersen_builtin,
            poseidon_builtin_applications: poseidon_builtin,
            ec_op_builtin_applications: ec_op_builtin,
            ecdsa_builtin_applications: ecdsa_builtin,
            bitwise_builtin_applications: bitwise_builtin,
            keccak_builtin_applications: keccak_builtin,
            segment_arena_builtin,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[cfg_attr(test, serde(rename_all = "SCREAMING_SNAKE_CASE"))]
pub enum ExecutionStatus {
    Succeeded,
    Reverted,
}

impl From<pathfinder_common::receipt::ExecutionStatus> for ExecutionStatus {
    fn from(value: pathfinder_common::receipt::ExecutionStatus) -> Self {
        match value {
            pathfinder_common::receipt::ExecutionStatus::Succeeded => Self::Succeeded,
            pathfinder_common::receipt::ExecutionStatus::Reverted { .. } => Self::Reverted,
        }
    }
}

impl crate::dto::SerializeForVersion for ExecutionStatus {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            Self::Succeeded => serializer.serialize_str("SUCCEEDED"),
            Self::Reverted => serializer.serialize_str("REVERTED"),
        }
    }
}

/// Message sent from L2 to L1.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct MessageToL1 {
    pub from_address: ContractAddress,
    pub to_address: ContractAddress,
    pub payload: Vec<L2ToL1MessagePayloadElem>,
}

impl From<pathfinder_common::receipt::L2ToL1Message> for MessageToL1 {
    fn from(value: pathfinder_common::receipt::L2ToL1Message) -> Self {
        Self {
            from_address: value.from_address,
            to_address: value.to_address,
            payload: value.payload,
        }
    }
}

impl crate::dto::SerializeForVersion for MessageToL1 {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("from_address", &self.from_address)?;
        serializer.serialize_field("to_address", &self.to_address)?;
        serializer.serialize_iter(
            "payload",
            self.payload.len(),
            &mut self.payload.iter().map(|p| RpcFelt(p.0)),
        )?;
        serializer.end()
    }
}

/// Event emitted as a part of a transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct Event {
    pub from_address: ContractAddress,
    pub keys: Vec<EventKey>,
    pub data: Vec<EventData>,
}

impl From<pathfinder_common::event::Event> for Event {
    fn from(e: pathfinder_common::event::Event) -> Self {
        Self {
            from_address: e.from_address,
            keys: e.keys,
            data: e.data,
        }
    }
}

impl crate::dto::SerializeForVersion for Event {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("from_address", &RpcFelt251(RpcFelt(self.from_address.0)))?;
        serializer.serialize_iter(
            "keys",
            self.keys.len(),
            &mut self.keys.iter().map(|k| RpcFelt(k.0)),
        )?;
        serializer.serialize_iter(
            "data",
            self.data.len(),
            &mut self.data.iter().map(|d| RpcFelt(d.0)),
        )?;
        serializer.end()
    }
}

/// Represents transaction status.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum TransactionStatus {
    AcceptedOnL2,
    AcceptedOnL1,
    Rejected,
}

impl From<BlockStatus> for TransactionStatus {
    fn from(status: BlockStatus) -> Self {
        match status {
            BlockStatus::Pending => TransactionStatus::AcceptedOnL2,
            BlockStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
            BlockStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
            BlockStatus::Rejected => TransactionStatus::Rejected,
        }
    }
}

impl crate::dto::SerializeForVersion for TransactionStatus {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str(match self {
            Self::AcceptedOnL2 => "ACCEPTED_ON_L2",
            Self::AcceptedOnL1 => "ACCEPTED_ON_L1",
            Self::Rejected => "REJECTED",
        })
    }
}
