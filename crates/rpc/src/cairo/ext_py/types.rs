use pathfinder_common::ContractAddress;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use stark_hash::Felt;

use crate::felt::RpcFelt;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionSimulation {
    pub trace: TransactionTrace,
    pub fee_estimation: FeeEstimate,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionTrace {
    pub revert_error: Option<String>,
    pub validate_invocation: Option<FunctionInvocation>,
    pub function_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub signature: Vec<Felt>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum CallType {
    #[serde(rename = "CALL")]
    Call,
    #[serde(rename = "DELEGATE")]
    Delegate,
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct Event {
    pub order: i64,
    #[serde_as(as = "Vec<RpcFelt>")]
    pub data: Vec<Felt>,
    #[serde_as(as = "Vec<RpcFelt>")]
    pub keys: Vec<Felt>,
}

#[serde_with::skip_serializing_none]
#[derive(Debug, Deserialize, Serialize)]
pub struct FunctionInvocation {
    pub calldata: Vec<Felt>,
    pub contract_address: ContractAddress,
    pub selector: Felt,
    #[serde(default)]
    pub call_type: Option<CallType>,
    #[serde(default)]
    pub caller_address: Option<Felt>,
    #[serde(default)]
    pub internal_calls: Option<Vec<FunctionInvocation>>,
    #[serde(default)]
    pub class_hash: Option<Felt>,
    #[serde(default)]
    pub entry_point_type: Option<EntryPointType>,
    #[serde(default)]
    pub events: Option<Vec<Event>>,
    #[serde(default)]
    pub messages: Option<Vec<MsgToL1>>,
    #[serde(default)]
    pub result: Option<Vec<Felt>>,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum EntryPointType {
    #[serde(rename = "CONSTRUCTOR")]
    Constructor,
    #[serde(rename = "EXTERNAL")]
    External,
    #[serde(rename = "L1_HANDLER")]
    L1Handler,
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct MsgToL1 {
    #[serde_as(as = "Vec<RpcFelt>")]
    pub payload: Vec<Felt>,
    #[serde_as(as = "RpcFelt")]
    pub to_address: Felt,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub overall_fee: primitive_types::U256,
}
