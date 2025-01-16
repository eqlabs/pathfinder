use std::collections::{BTreeMap, HashSet};

use blockifier::execution::call_info::OrderedL2ToL1Message;
use blockifier::transaction::objects::TransactionExecutionInfo;
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
use starknet_api::block::{BlockInfo, FeeType};
use starknet_api::execution_resources::GasVector;

use super::felt::IntoFelt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FeeEstimate {
    pub l1_gas_consumed: primitive_types::U256,
    pub l1_gas_price: primitive_types::U256,
    pub l1_data_gas_consumed: primitive_types::U256,
    pub l1_data_gas_price: primitive_types::U256,
    pub l2_gas_consumed: primitive_types::U256,
    pub l2_gas_price: primitive_types::U256,
    pub overall_fee: primitive_types::U256,
    pub unit: PriceUnit,
}

impl FeeEstimate {
    /// Computes fee estimate from the transaction execution information.
    pub(crate) fn from_tx_info_and_gas_price(
        tx_info: &TransactionExecutionInfo,
        block_info: &BlockInfo,
        fee_type: FeeType,
        minimal_l1_gas_amount_vector: &Option<GasVector>,
    ) -> FeeEstimate {
        tracing::trace!(resources=?tx_info.receipt.resources, "Transaction resources");
        let gas_prices = block_info.gas_prices.gas_price_vector(&fee_type);
        let l1_gas_price = gas_prices.l1_gas_price.get();
        let l1_data_gas_price = gas_prices.l1_data_gas_price.get();
        let l2_gas_price = gas_prices.l2_gas_price.get();

        let minimal_l1_gas_amount_vector = minimal_l1_gas_amount_vector.unwrap_or_default();

        let l1_gas_consumed = tx_info
            .receipt
            .gas
            .l1_gas
            .max(minimal_l1_gas_amount_vector.l1_gas);
        let l1_data_gas_consumed = tx_info
            .receipt
            .gas
            .l1_data_gas
            .max(minimal_l1_gas_amount_vector.l1_data_gas);
        let l2_gas_consumed = tx_info.receipt.gas.l2_gas;

        // Blockifier does not put the actual fee into the receipt if `max_fee` in the
        // transaction was zero. In that case we have to compute the fee
        // explicitly.
        let overall_fee = blockifier::fee::fee_utils::get_fee_by_gas_vector(
            block_info,
            GasVector {
                l1_gas: l1_gas_consumed,
                l1_data_gas: l1_data_gas_consumed,
                l2_gas: l2_gas_consumed,
            },
            &fee_type,
        )
        .0;

        FeeEstimate {
            l1_gas_consumed: l1_gas_consumed.0.into(),
            l1_gas_price: l1_gas_price.0.into(),
            l1_data_gas_consumed: l1_data_gas_consumed.0.into(),
            l1_data_gas_price: l1_data_gas_price.0.into(),
            l2_gas_consumed: l2_gas_consumed.0.into(),
            l2_gas_price: l2_gas_price.0.into(),
            overall_fee: overall_fee.into(),
            unit: fee_type.into(),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PriceUnit {
    Wei,
    Fri,
}

impl From<FeeType> for PriceUnit {
    fn from(value: FeeType) -> Self {
        match value {
            FeeType::Strk => Self::Fri,
            FeeType::Eth => Self::Wei,
        }
    }
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
#[allow(clippy::large_enum_variant)]
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
    pub execution_resources: InnerCallExecutionResources,
    pub is_reverted: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MsgToL1 {
    pub order: usize,
    pub payload: Vec<Felt>,
    pub to_address: Felt,
    pub from_address: Felt,
}

#[derive(Default, Debug, Clone)]
pub struct InnerCallExecutionResources {
    pub l1_gas: u128,
    pub l2_gas: u128,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
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
    pub l1_gas: u128,
    pub l1_data_gas: u128,
    pub l2_gas: u128,
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

// Non-recursive variant of `CallInfo::summarize()`
fn summarize_call_info(
    call_info: &blockifier::execution::call_info::CallInfo,
) -> blockifier::execution::call_info::ExecutionSummary {
    let class_hash = call_info
        .call
        .class_hash
        .expect("Class hash must be set after execution.");
    let executed_class_hashes: HashSet<starknet_api::core::ClassHash> =
        std::iter::once(class_hash).collect();

    // Storage entries.
    let visited_storage_entries = call_info
        .accessed_storage_keys
        .iter()
        .map(|storage_key| (call_info.call.storage_address, *storage_key))
        .collect();

    // Messages.
    let l2_to_l1_payload_lengths = call_info
        .execution
        .l2_to_l1_messages
        .iter()
        .map(|message| message.message.payload.0.len())
        .collect();

    let event_summary = specific_event_summary(call_info);

    let inner_call_execution_resources = call_info.inner_calls.iter().fold(
        cairo_vm::vm::runners::cairo_runner::ExecutionResources::default(),
        |acc, call_info| &acc + &call_info.resources,
    );
    let non_recursive_vm_resources = &call_info.resources - &inner_call_execution_resources;

    blockifier::execution::call_info::ExecutionSummary {
        charged_resources: blockifier::execution::call_info::ChargedResources {
            vm_resources: non_recursive_vm_resources,
            gas_consumed: starknet_api::execution_resources::GasAmount(
                call_info.execution.gas_consumed,
            ),
        },
        executed_class_hashes,
        visited_storage_entries,
        l2_to_l1_payload_lengths,
        event_summary,
    }
}

// Copy of `CallInfo::specific_event_summary()` because that is private
fn specific_event_summary(
    call_info: &blockifier::execution::call_info::CallInfo,
) -> blockifier::execution::call_info::EventSummary {
    let mut event_summary = blockifier::execution::call_info::EventSummary {
        n_events: call_info.execution.events.len(),
        ..Default::default()
    };
    for blockifier::execution::call_info::OrderedEvent { event, .. } in
        call_info.execution.events.iter()
    {
        let data_len: u64 = event
            .data
            .0
            .len()
            .try_into()
            .expect("Conversion from usize to u64 should not fail.");
        event_summary.total_event_data_size += data_len;
        let key_len: u64 = event
            .keys
            .len()
            .try_into()
            .expect("Conversion from usize to u64 should not fail.");
        event_summary.total_event_keys += key_len;
    }
    event_summary
}

impl FunctionInvocation {
    pub fn from_call_info(
        call_info: blockifier::execution::call_info::CallInfo,
        versioned_constants: &blockifier::versioned_constants::VersionedConstants,
        gas_vector_computation_mode: &starknet_api::transaction::fields::GasVectorComputationMode,
    ) -> Self {
        let execution_summary = summarize_call_info(&call_info);

        // Message costs
        let message_resources = blockifier::fee::resources::MessageResources::new(
            execution_summary.l2_to_l1_payload_lengths,
            None,
        );
        let message_gas_cost = message_resources.to_gas_vector();

        // Event costs
        let archival_gas_costs = &versioned_constants.deprecated_l2_resource_gas_costs;
        let event_gas_cost = GasVector::from_l1_gas(
            (archival_gas_costs.gas_per_data_felt
                * (archival_gas_costs.event_key_factor
                    * execution_summary.event_summary.total_event_keys
                    + execution_summary.event_summary.total_event_data_size))
                .to_integer()
                .into(),
        );

        // Computation costs
        let computation_resources = blockifier::fee::resources::ComputationResources {
            vm_resources: execution_summary
                .charged_resources
                .vm_resources
                .filter_unused_builtins(),
            n_reverted_steps: 0,
            sierra_gas: execution_summary.charged_resources.gas_consumed,
            reverted_sierra_gas: 0u64.into(),
        };
        let computation_gas_cost =
            computation_resources.to_gas_vector(versioned_constants, gas_vector_computation_mode);

        let gas_vector = computation_gas_cost
            .checked_add(event_gas_cost)
            .unwrap_or_else(|| panic!("resource overflow while adding event costs"))
            .checked_add(message_gas_cost)
            .unwrap_or_else(|| panic!("resource overflow while adding message costs"));

        let messages = ordered_l2_to_l1_messages(&call_info);

        let internal_calls = call_info
            .inner_calls
            .into_iter()
            .map(|call_info| {
                Self::from_call_info(call_info, versioned_constants, gas_vector_computation_mode)
            })
            .collect();

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
            execution_resources: InnerCallExecutionResources {
                l1_gas: gas_vector.l1_gas.0.into(),
                l2_gas: gas_vector.l2_gas.0.into(),
            },
            is_reverted: call_info.execution.failed,
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

impl From<starknet_api::contract_class::EntryPointType> for EntryPointType {
    fn from(value: starknet_api::contract_class::EntryPointType) -> Self {
        use starknet_api::contract_class::EntryPointType::*;
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
