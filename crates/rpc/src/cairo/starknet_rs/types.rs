use serde::Serialize;
use serde_with::serde_as;

use pathfinder_common::ContractAddress;

use stark_hash::Felt;

use super::felt::IntoFelt;

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub overall_fee: primitive_types::U256,
}

#[derive(Debug, Eq, PartialEq)]
pub enum EntryPointType {
    Constructor,
    External,
    L1Handler,
}

#[derive(Debug)]
pub struct TransactionSimulation {
    pub trace: TransactionTrace,
    pub fee_estimation: FeeEstimate,
}

#[derive(Debug)]
pub enum TransactionTrace {
    Declare(DeclareTransactionTrace),
    DeployAccount(DeployAccountTransactionTrace),
    Invoke(InvokeTransactionTrace),
    L1Handler(L1HandlerTransactionTrace),
}

#[derive(Debug)]
pub struct DeclareTransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
}

#[derive(Debug)]
pub struct DeployAccountTransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub constructor_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
}

#[derive(Debug)]
pub struct InvokeTransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub execute_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
}

#[derive(Debug)]
pub struct L1HandlerTransactionTrace {
    pub function_invocation: Option<FunctionInvocation>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum CallType {
    Call,
    Delegate,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Event {
    pub order: i64,
    pub data: Vec<Felt>,
    pub keys: Vec<Felt>,
}

#[derive(Debug)]
pub struct FunctionInvocation {
    pub calldata: Vec<Felt>,
    pub contract_address: ContractAddress,
    pub selector: Felt,
    pub call_type: Option<CallType>,
    pub caller_address: Felt,
    pub internal_calls: Vec<FunctionInvocation>,
    pub class_hash: Option<Felt>,
    pub entry_point_type: Option<EntryPointType>,
    pub events: Vec<Event>,
    pub messages: Vec<MsgToL1>,
    pub result: Vec<Felt>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct MsgToL1 {
    pub payload: Vec<Felt>,
    pub to_address: Felt,
    pub from_address: Felt,
}

impl TryFrom<starknet_in_rust::execution::CallInfo> for FunctionInvocation {
    type Error = starknet_in_rust::transaction::error::TransactionError;

    fn try_from(call_info: starknet_in_rust::execution::CallInfo) -> Result<Self, Self::Error> {
        let messages = call_info
            .get_sorted_l2_to_l1_messages()?
            .into_iter()
            .map(Into::into)
            .collect();

        let internal_calls = call_info
            .internal_calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        let events = call_info.events.into_iter().map(Into::into).collect();

        let result = call_info
            .retdata
            .into_iter()
            .map(IntoFelt::into_felt)
            .collect();

        Ok(Self {
            calldata: call_info
                .calldata
                .into_iter()
                .map(IntoFelt::into_felt)
                .collect(),
            contract_address: ContractAddress::new_or_panic(
                call_info.contract_address.0.into_felt(),
            ),
            selector: call_info
                .entry_point_selector
                .map(|s| s.into_felt())
                .unwrap_or(Felt::ZERO),
            call_type: call_info.call_type.map(Into::into),
            caller_address: call_info.caller_address.0.into_felt(),
            internal_calls,
            class_hash: call_info
                .class_hash
                .and_then(|class_hash| Felt::from_be_bytes(class_hash).ok()),
            entry_point_type: call_info.entry_point_type.map(Into::into),
            events,
            messages,
            result,
        })
    }
}

impl From<starknet_in_rust::execution::CallType> for CallType {
    fn from(value: starknet_in_rust::execution::CallType) -> Self {
        match value {
            starknet_in_rust::execution::CallType::Call => CallType::Call,
            starknet_in_rust::execution::CallType::Delegate => CallType::Delegate,
        }
    }
}

impl From<starknet_in_rust::services::api::contract_classes::deprecated_contract_class::EntryPointType> for EntryPointType {
    fn from(value: starknet_in_rust::services::api::contract_classes::deprecated_contract_class::EntryPointType) -> Self {
        match value {
            starknet_in_rust::EntryPointType::External => EntryPointType::External,
            starknet_in_rust::EntryPointType::L1Handler => EntryPointType::L1Handler,
            starknet_in_rust::EntryPointType::Constructor => EntryPointType::Constructor,
        }
    }
}

impl From<starknet_in_rust::execution::OrderedEvent> for Event {
    fn from(value: starknet_in_rust::execution::OrderedEvent) -> Self {
        Self {
            order: value.order as i64,
            data: value.data.into_iter().map(IntoFelt::into_felt).collect(),
            keys: value.keys.into_iter().map(IntoFelt::into_felt).collect(),
        }
    }
}

impl From<starknet_in_rust::execution::L2toL1MessageInfo> for MsgToL1 {
    fn from(value: starknet_in_rust::execution::L2toL1MessageInfo) -> Self {
        Self {
            payload: value.payload.into_iter().map(IntoFelt::into_felt).collect(),
            to_address: value.to_address.0.into_felt(),
            from_address: value.from_address.0.into_felt(),
        }
    }
}
