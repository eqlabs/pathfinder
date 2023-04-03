use pathfinder_common::ContractAddress;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use stark_hash::Felt;

use crate::v03::method::simulate_transaction::dto::{CallType, EntryPointType, Event, MsgToL1};

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
