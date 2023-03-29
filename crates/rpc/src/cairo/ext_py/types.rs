use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use stark_hash::Felt;

use crate::v03::method::simulate_transaction::dto::{
    Address, CallType, EntryPointType, Event, MsgToL1,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionSimulation {
    pub trace: TransactionTrace,
    pub fee_estimation: FeeEstimate,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub function_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub signature: Vec<Felt>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct FunctionInvocation {
    pub calldata: Vec<Felt>,
    pub contract_address: Address,
    pub selector: Felt,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_type: Option<CallType>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_address: Option<Felt>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_calls: Option<Vec<FunctionInvocation>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub class_hash: Option<Felt>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_point_type: Option<EntryPointType>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<Event>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<MsgToL1>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Vec<Felt>>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
    pub gas_consumed: ethers::types::H256,
    #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
    pub gas_price: ethers::types::H256,
    #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
    pub overall_fee: ethers::types::H256,
}
