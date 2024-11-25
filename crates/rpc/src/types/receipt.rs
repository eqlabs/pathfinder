use pathfinder_common::{
    BlockHash,
    BlockNumber,
    ContractAddress,
    EventData,
    EventKey,
    Fee,
    L2ToL1MessagePayloadElem,
    TransactionHash,
};
use pathfinder_serde::H256AsNoLeadingZerosHexStr;
use primitive_types::H256;
use serde::Serialize;
use serde_with::serde_as;

use crate::felt::{RpcFelt, RpcFelt251};
use crate::types::reply::BlockStatus;
use crate::types::PriceUnit;

/// Invoke transaction receipt as returned by the RPC API.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct InvokeTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonTransactionReceiptProperties,
}

/// Common properties of a transaction receipt as returned by the RPC API.
#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct CommonTransactionReceiptProperties {
    #[serde_as(as = "RpcFelt")]
    pub transaction_hash: TransactionHash,
    pub actual_fee: FeePayment,
    #[serde_as(as = "RpcFelt")]
    pub block_hash: BlockHash,
    pub block_number: BlockNumber,
    pub messages_sent: Vec<MessageToL1>,
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    pub execution_resources: ExecutionResourcesProperties,
    pub execution_status: ExecutionStatus,
    pub finality_status: FinalityStatus,
}

/// Common properties of a pending transaction receipt as returned by the RPC
/// API.
#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct CommonPendingTransactionReceiptProperties {
    pub transaction_hash: TransactionHash,
    pub actual_fee: FeePayment,
    pub messages_sent: Vec<MessageToL1>,
    pub events: Vec<Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revert_reason: Option<String>,
    pub execution_status: ExecutionStatus,
    pub execution_resources: ExecutionResourcesProperties,
    pub finality_status: FinalityStatus,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(untagged)]
pub enum FeePayment {
    V06 { amount: Fee, unit: PriceUnit },
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct ExecutionResourcesProperties {
    pub steps: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub memory_holes: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub range_check_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub pedersen_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub poseidon_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub ec_op_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub ecdsa_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub bitwise_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub keccak_builtin_applications: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub segment_arena_builtin: u64,
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

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(test, derive(serde::Deserialize))]
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

#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(test, derive(serde::Deserialize))]
pub enum FinalityStatus {
    AcceptedOnL2,
    AcceptedOnL1,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct L1HandlerTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonTransactionReceiptProperties,
    #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
    pub message_hash: H256,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct DeployTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonTransactionReceiptProperties,
    #[serde_as(as = "RpcFelt251")]
    pub contract_address: ContractAddress,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct DeployAccountTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonTransactionReceiptProperties,
    #[serde_as(as = "RpcFelt251")]
    pub contract_address: ContractAddress,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct DeclareTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonTransactionReceiptProperties,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct PendingInvokeTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonPendingTransactionReceiptProperties,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct PendingDeclareTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonPendingTransactionReceiptProperties,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct PendingDeployTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonPendingTransactionReceiptProperties,
    pub contract_address: ContractAddress,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct PendingDeployAccountTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonPendingTransactionReceiptProperties,
    pub contract_address: ContractAddress,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
pub struct PendingL1HandlerTransactionReceipt {
    #[serde(flatten)]
    pub common: CommonPendingTransactionReceiptProperties,
    #[serde_as(as = "H256AsNoLeadingZerosHexStr")]
    pub message_hash: H256,
}

/// Message sent from L2 to L1.
#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(deny_unknown_fields)]
pub struct MessageToL1 {
    pub from_address: ContractAddress,
    pub to_address: ContractAddress,
    #[serde_as(as = "Vec<RpcFelt>")]
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

/// Event emitted as a part of a transaction.
#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(deny_unknown_fields)]
pub struct Event {
    #[serde_as(as = "RpcFelt251")]
    pub from_address: ContractAddress,
    #[serde_as(as = "Vec<RpcFelt>")]
    pub keys: Vec<EventKey>,
    #[serde_as(as = "Vec<RpcFelt>")]
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

/// Represents transaction status.
#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Deserialize))]
#[serde(deny_unknown_fields)]
pub enum TransactionStatus {
    #[serde(rename = "ACCEPTED_ON_L2")]
    AcceptedOnL2,
    #[serde(rename = "ACCEPTED_ON_L1")]
    AcceptedOnL1,
    #[serde(rename = "REJECTED")]
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
