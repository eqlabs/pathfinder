use std::collections::{BTreeMap, HashSet};

use blockifier::execution::call_info::OrderedL2ToL1Message;
use blockifier::transaction::objects::{GasVector, TransactionExecutionInfo};
use pathfinder_common::{
    CasmHash,
    ClassHash,
    ContractAddress,
    ContractNonce,
    SierraHash,
    StorageAddress,
    StorageValue,
};
use pathfinder_crypto::Felt;

use super::felt::IntoFelt;

#[derive(Debug)]
pub struct FeeEstimate {
    pub gas_consumed: primitive_types::U256,
    pub gas_price: primitive_types::U256,
    pub data_gas_consumed: primitive_types::U256,
    pub data_gas_price: primitive_types::U256,
    pub overall_fee: primitive_types::U256,
    pub unit: PriceUnit,
}

impl FeeEstimate {
    /// Computes fee estimate from the transaction execution information.
    pub(crate) fn from_tx_info_and_gas_price(
        tx_info: &TransactionExecutionInfo,
        gas_price: u128,
        data_gas_price: u128,
        unit: PriceUnit,
        minimal_l1_gas_amount_vector: Option<GasVector>,
    ) -> FeeEstimate {
        let gas_consumed = tx_info.transaction_receipt.gas.l1_gas;
        let data_gas_consumed = tx_info.transaction_receipt.gas.l1_data_gas;

        let (minimal_gas_consumed, minimal_data_gas_consumed) = minimal_l1_gas_amount_vector
            .map(|v| (v.l1_gas, v.l1_data_gas))
            .unwrap_or_default();

        let gas_consumed = gas_consumed.max(minimal_gas_consumed);
        let data_gas_consumed = data_gas_consumed.max(minimal_data_gas_consumed);

        let overall_fee = tx_info.transaction_receipt.fee.0;

        FeeEstimate {
            gas_consumed: gas_consumed.into(),
            gas_price: gas_price.into(),
            data_gas_consumed: data_gas_consumed.into(),
            data_gas_price: data_gas_price.into(),
            overall_fee: overall_fee.into(),
            unit,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum PriceUnit {
    Wei,
    Fri,
}

#[derive(Debug, Clone, Eq, PartialEq)]
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

impl TransactionSimulation {
    pub fn revert_reason(&self) -> Option<&str> {
        self.trace.revert_reason()
    }
}

#[derive(Debug, Clone)]
pub enum TransactionTrace {
    Declare(DeclareTransactionTrace),
    DeployAccount(DeployAccountTransactionTrace),
    Invoke(InvokeTransactionTrace),
    L1Handler(L1HandlerTransactionTrace),
}

impl TransactionTrace {
    fn revert_reason(&self) -> Option<&str> {
        match self {
            TransactionTrace::Invoke(InvokeTransactionTrace {
                execute_invocation: ExecuteInvocation::RevertedReason(revert_reason),
                ..
            }) => Some(revert_reason.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeclareTransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub state_diff: StateDiff,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone)]
pub struct DeployAccountTransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub constructor_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub state_diff: StateDiff,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone)]
pub enum ExecuteInvocation {
    FunctionInvocation(Option<FunctionInvocation>),
    RevertedReason(String),
}

#[derive(Debug, Clone)]
pub struct InvokeTransactionTrace {
    pub validate_invocation: Option<FunctionInvocation>,
    pub execute_invocation: ExecuteInvocation,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub state_diff: StateDiff,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone)]
pub struct L1HandlerTransactionTrace {
    pub function_invocation: Option<FunctionInvocation>,
    pub state_diff: StateDiff,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CallType {
    Call,
    Delegate,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Event {
    pub order: i64,
    pub data: Vec<Felt>,
    pub keys: Vec<Felt>,
}

#[derive(Debug, Clone)]
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
    pub computation_resources: ComputationResources,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MsgToL1 {
    pub order: usize,
    pub payload: Vec<Felt>,
    pub to_address: Felt,
    pub from_address: Felt,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StateDiff {
    pub storage_diffs: BTreeMap<ContractAddress, Vec<StorageDiff>>,
    pub deployed_contracts: Vec<DeployedContract>,
    pub deprecated_declared_classes: HashSet<ClassHash>,
    pub declared_classes: Vec<DeclaredSierraClass>,
    pub nonces: BTreeMap<ContractAddress, ContractNonce>,
    pub replaced_classes: Vec<ReplacedClass>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StorageDiff {
    pub key: StorageAddress,
    pub value: StorageValue,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeployedContract {
    pub address: ContractAddress,
    pub class_hash: ClassHash,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeclaredSierraClass {
    pub class_hash: SierraHash,
    pub compiled_class_hash: CasmHash,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReplacedClass {
    pub contract_address: ContractAddress,
    pub class_hash: ClassHash,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ExecutionResources {
    pub computation_resources: ComputationResources,
    pub data_availability: DataAvailabilityResources,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ComputationResources {
    pub steps: usize,
    pub memory_holes: usize,
    pub range_check_builtin_applications: usize,
    pub pedersen_builtin_applications: usize,
    pub poseidon_builtin_applications: usize,
    pub ec_op_builtin_applications: usize,
    pub ecdsa_builtin_applications: usize,
    pub bitwise_builtin_applications: usize,
    pub keccak_builtin_applications: usize,
    pub segment_arena_builtin: usize,
}

impl std::ops::Add for ComputationResources {
    type Output = ComputationResources;

    fn add(self, rhs: Self) -> Self::Output {
        Self::Output {
            steps: self.steps + rhs.steps,
            memory_holes: self.memory_holes + rhs.memory_holes,
            range_check_builtin_applications: self.range_check_builtin_applications
                + rhs.range_check_builtin_applications,
            pedersen_builtin_applications: self.pedersen_builtin_applications
                + rhs.pedersen_builtin_applications,
            poseidon_builtin_applications: self.poseidon_builtin_applications
                + rhs.poseidon_builtin_applications,
            ec_op_builtin_applications: self.ec_op_builtin_applications
                + rhs.ec_op_builtin_applications,
            ecdsa_builtin_applications: self.ecdsa_builtin_applications
                + rhs.ecdsa_builtin_applications,
            bitwise_builtin_applications: self.bitwise_builtin_applications
                + rhs.bitwise_builtin_applications,
            keccak_builtin_applications: self.keccak_builtin_applications
                + rhs.keccak_builtin_applications,
            segment_arena_builtin: self.segment_arena_builtin + rhs.segment_arena_builtin,
        }
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct DataAvailabilityResources {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
}

impl From<blockifier::execution::call_info::CallInfo> for FunctionInvocation {
    fn from(call_info: blockifier::execution::call_info::CallInfo) -> Self {
        let messages = ordered_l2_to_l1_messages(&call_info);

        let internal_calls = call_info.inner_calls.into_iter().map(Into::into).collect();

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

        Self {
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
            computation_resources: call_info.resources.into(),
        }
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

    for OrderedL2ToL1Message { order, message } in &call_info.execution.l2_to_l1_messages {
        messages.insert(
            order,
            MsgToL1 {
                order: *order,
                payload: message.payload.0.iter().map(IntoFelt::into_felt).collect(),
                to_address: Felt::from_be_slice(message.to_address.0.as_bytes())
                    .expect("Ethereum address should fit into felt"),
                from_address: call_info.call.storage_address.0.key().into_felt(),
            },
        );
    }

    messages.into_values().collect()
}

impl From<cairo_vm::vm::runners::cairo_runner::ExecutionResources> for ComputationResources {
    fn from(value: cairo_vm::vm::runners::cairo_runner::ExecutionResources) -> Self {
        use cairo_vm::types::builtin_name::BuiltinName;

        Self {
            steps: value.n_steps,
            memory_holes: value.n_memory_holes,
            range_check_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::range_check)
                .unwrap_or(&0),
            pedersen_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::pedersen)
                .unwrap_or(&0),
            poseidon_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::poseidon)
                .unwrap_or(&0),
            ec_op_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::ec_op)
                .unwrap_or(&0),
            ecdsa_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::ecdsa)
                .unwrap_or(&0),
            bitwise_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::bitwise)
                .unwrap_or(&0),
            keccak_builtin_applications: *value
                .builtin_instance_counter
                .get(&BuiltinName::keccak)
                .unwrap_or(&0),
            segment_arena_builtin: *value
                .builtin_instance_counter
                .get(&BuiltinName::segment_arena)
                .unwrap_or(&0),
        }
    }
}
