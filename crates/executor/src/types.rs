use std::collections::BTreeMap;

use blockifier::execution::call_info::OrderedL2ToL1Message;
use pathfinder_common::ContractAddress;
use stark_hash::Felt;

use super::felt::IntoFelt;

#[derive(Debug)]
pub struct FeeEstimate {
    pub gas_consumed: primitive_types::U256,
    pub gas_price: primitive_types::U256,
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
    pub call_type: CallType,
    pub caller_address: Felt,
    pub internal_calls: Vec<FunctionInvocation>,
    pub class_hash: Option<Felt>,
    pub entry_point_type: EntryPointType,
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

impl TryFrom<blockifier::execution::call_info::CallInfo> for FunctionInvocation {
    type Error = blockifier::transaction::errors::TransactionExecutionError;

    fn try_from(
        call_info: blockifier::execution::call_info::CallInfo,
    ) -> Result<Self, Self::Error> {
        call_info.get_sorted_l2_to_l1_payloads_length()?;
        let messages = ordered_l2_to_l1_messages(&call_info);

        let internal_calls = call_info
            .inner_calls
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        let events = call_info
            .execution
            .events
            .into_iter()
            .map(Into::into)
            .collect();

        let result = call_info
            .execution
            .retdata
            .0
            .into_iter()
            .map(IntoFelt::into_felt)
            .collect();

        Ok(Self {
            calldata: call_info
                .call
                .calldata
                .0
                .iter()
                .map(IntoFelt::into_felt)
                .collect(),
            contract_address: ContractAddress::new_or_panic(
                call_info.call.storage_address.0.key().into_felt(),
            ),
            selector: call_info.call.entry_point_selector.0.into_felt(),
            call_type: call_info.call.call_type.into(),
            caller_address: call_info.call.caller_address.0.key().into_felt(),
            internal_calls,
            class_hash: call_info
                .call
                .class_hash
                .map(|class_hash| class_hash.0.into_felt()),
            entry_point_type: call_info.call.entry_point_type.into(),
            events,
            messages,
            result,
        })
    }
}

impl From<blockifier::execution::entry_point::CallType> for CallType {
    fn from(value: blockifier::execution::entry_point::CallType) -> Self {
        use blockifier::execution::entry_point::CallType::*;
        match value {
            Call => CallType::Call,
            Delegate => CallType::Delegate,
        }
    }
}

impl From<starknet_api::deprecated_contract_class::EntryPointType> for EntryPointType {
    fn from(value: starknet_api::deprecated_contract_class::EntryPointType) -> Self {
        use starknet_api::deprecated_contract_class::EntryPointType::*;
        match value {
            External => EntryPointType::External,
            L1Handler => EntryPointType::L1Handler,
            Constructor => EntryPointType::Constructor,
        }
    }
}

impl From<blockifier::execution::call_info::OrderedEvent> for Event {
    fn from(value: blockifier::execution::call_info::OrderedEvent) -> Self {
        Self {
            order: value.order as i64,
            data: value
                .event
                .data
                .0
                .into_iter()
                .map(IntoFelt::into_felt)
                .collect(),
            keys: value
                .event
                .keys
                .into_iter()
                .map(|key| key.0.into_felt())
                .collect(),
        }
    }
}

fn ordered_l2_to_l1_messages(
    call_info: &blockifier::execution::call_info::CallInfo,
) -> Vec<MsgToL1> {
    let mut messages = BTreeMap::new();

    for call in call_info.into_iter() {
        for OrderedL2ToL1Message { order, message } in &call.execution.l2_to_l1_messages {
            messages.insert(
                order,
                MsgToL1 {
                    payload: message.payload.0.iter().map(IntoFelt::into_felt).collect(),
                    to_address: Felt::from_be_slice(message.to_address.0.as_bytes())
                        .expect("Ethereum address should fit into felt"),
                    from_address: call.call.storage_address.0.key().into_felt(),
                },
            );
        }
    }

    messages.into_values().collect()
}
