use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use anyhow::Context;
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::execution::call_info::{CallInfo, OrderedL2ToL1Message};
use blockifier::state::cached_state::StateMaps;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateReader as _;
use blockifier::transaction::transaction_execution::Transaction;
use pathfinder_common::prelude::*;
use pathfinder_common::state_update::{
    ContractClassUpdate,
    ContractUpdate,
    StateUpdateData,
    SystemContractUpdate,
};
use pathfinder_common::transaction::TransactionVariant;
use pathfinder_crypto::Felt;
use starknet_api::block::FeeType;
use starknet_api::core::PatriciaKey;
use starknet_api::execution_resources::{GasAmount, GasVector};
use starknet_api::transaction::fields::{
    AccountDeploymentData,
    AllResourceBounds,
    Calldata,
    GasVectorComputationMode,
    PaymasterData,
    TransactionSignature,
    ValidResourceBounds,
};

use super::felt::IntoFelt;
use crate::execution_state::PathfinderExecutionState;
use crate::state_reader::StorageAdapter;
use crate::IntoStarkFelt as _;

pub const ETH_TO_WEI_RATE: u128 = 1_000_000_000_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub actual_fee: Fee,
    // TODO(validator) currently there's a mismatch between reexecution and historical receipts but
    // it does not impact the commitment
    pub execution_resources: pathfinder_common::receipt::ExecutionResources,
    pub l2_to_l1_messages: Vec<pathfinder_common::receipt::L2ToL1Message>,
    pub execution_status: pathfinder_common::receipt::ExecutionStatus,
    pub transaction_index: TransactionIndex,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockInfo {
    pub number: BlockNumber,
    pub timestamp: BlockTimestamp,
    pub eth_l1_gas_price: GasPrice,
    pub strk_l1_gas_price: GasPrice,
    pub eth_l1_data_gas_price: GasPrice,
    pub strk_l1_data_gas_price: GasPrice,
    pub eth_l2_gas_price: GasPrice,
    pub strk_l2_gas_price: GasPrice,
    pub sequencer_address: SequencerAddress,
    pub starknet_version: StarknetVersion,
    pub l1_da_mode: L1DataAvailabilityMode,
}

impl From<BlockHeader> for BlockInfo {
    fn from(h: BlockHeader) -> Self {
        Self {
            number: h.number,
            timestamp: h.timestamp,
            eth_l1_gas_price: h.eth_l1_gas_price,
            strk_l1_gas_price: h.strk_l1_gas_price,
            eth_l1_data_gas_price: h.eth_l1_data_gas_price,
            strk_l1_data_gas_price: h.strk_l1_data_gas_price,
            eth_l2_gas_price: h.eth_l2_gas_price,
            strk_l2_gas_price: h.strk_l2_gas_price,
            sequencer_address: h.sequencer_address,
            starknet_version: h.starknet_version,
            l1_da_mode: h.l1_da_mode,
        }
    }
}

impl BlockInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_proposal(
        height: u64,
        timestamp: u64,
        builder: SequencerAddress,
        l1_da_mode: L1DataAvailabilityMode,
        l2_gas_price_fri: u128,
        l1_gas_price_wei: u128,
        l1_data_gas_price_wei: u128,
        // TODO(validator) ignored for the time being, see comment below
        eth_to_fri_rate: u128,
        starknet_version: StarknetVersion,
        // TODO(validator)
        // one eth_to_fri_rate is not suitable for current sepolia or integration data
        // where there are 3 pairs of gas prices in both wei & fri and they give
        // 2 different ethfri rates, often due to one of the prices in wei saturated at 1
        workaround_l2_gas_price_wei: u128,
        workaround_l1_gas_price_fri: u128,
        workaround_l1_data_gas_price_fri: u128,
    ) -> anyhow::Result<Self> {
        let _wei_to_fri = |wei: u128| -> u128 { wei * eth_to_fri_rate / ETH_TO_WEI_RATE };
        let _fri_to_wei = |fri: u128| -> u128 { fri * ETH_TO_WEI_RATE / eth_to_fri_rate };

        let number = BlockNumber::new(height).context("Proposal height exceeds i64::MAX")?;
        let timestamp =
            BlockTimestamp::new(timestamp).context("Proposal timestamp exceeds i64::MAX")?;
        let eth_l1_gas_price = GasPrice(l1_gas_price_wei);
        // TODO(validator)
        // let strk_l1_gas_price = GasPrice(wei_to_fri(l1_gas_price_wei));
        let strk_l1_gas_price = GasPrice(workaround_l1_gas_price_fri);
        let eth_l1_data_gas_price = GasPrice(l1_data_gas_price_wei);
        // TODO(validator)
        // let strk_l1_data_gas_price = GasPrice(wei_to_fri(l1_data_gas_price_wei));
        let strk_l1_data_gas_price = GasPrice(workaround_l1_data_gas_price_fri);
        // TODO(validator)
        // let eth_l2_gas_price = GasPrice(fri_to_wei(l2_gas_price_fri));
        let eth_l2_gas_price = GasPrice(workaround_l2_gas_price_wei);
        let strk_l2_gas_price = GasPrice(l2_gas_price_fri);
        Ok(Self {
            number,
            timestamp,
            eth_l1_gas_price,
            strk_l1_gas_price,
            eth_l1_data_gas_price,
            strk_l1_data_gas_price,
            eth_l2_gas_price,
            strk_l2_gas_price,
            sequencer_address: builder,
            starknet_version,
            l1_da_mode,
        })
    }
}

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
    pub(crate) fn from_gas_vector_and_gas_price(
        gas_vector: &GasVector,
        block_context: &blockifier::context::BlockContext,
        fee_type: FeeType,
        gas_vector_computation_mode: &GasVectorComputationMode,
        tip: starknet_api::transaction::fields::Tip,
        minimal_gas_vector: &Option<GasVector>,
    ) -> FeeEstimate {
        tracing::trace!(?gas_vector, "Transaction resources");
        let gas_prices = block_context
            .block_info()
            .gas_prices
            .gas_price_vector(&fee_type);
        let l1_gas_price = gas_prices.l1_gas_price.get();
        let l1_data_gas_price = gas_prices.l1_data_gas_price.get();
        let l2_gas_price = gas_prices.l2_gas_price.get();

        let minimal_gas_vector = minimal_gas_vector.unwrap_or_default();

        let adjusted_gas_vector = GasVector {
            l1_gas: gas_vector.l1_gas.max(minimal_gas_vector.l1_gas),
            l1_data_gas: gas_vector.l1_data_gas.max(minimal_gas_vector.l1_data_gas),
            l2_gas: gas_vector.l2_gas.max(minimal_gas_vector.l2_gas),
        };

        // In some cases (like: L1 handler transactions with blockifier >= 0.15.0) we
        // may have L2 gas in the gas vector even though the gas vector
        // computation mode (derived from the transaction type) is set to
        // `NoL2Gas`. In that case we need to convert the L2 gas to L1
        // gas and add it to the L1 gas amount.
        let adjusted_gas_vector = match gas_vector_computation_mode {
            GasVectorComputationMode::All => adjusted_gas_vector,
            GasVectorComputationMode::NoL2Gas => GasVector {
                l1_gas: adjusted_gas_vector
                    .l1_gas
                    .checked_add(
                        block_context
                            .versioned_constants()
                            .sierra_gas_to_l1_gas_amount_round_up(adjusted_gas_vector.l2_gas),
                    )
                    .unwrap_or_else(|| {
                        panic!(
                            "L1 gas amount overflowed: addition of converted L2 gas ({}) to L1 \
                             gas ({}) resulted in overflow.",
                            adjusted_gas_vector.l2_gas, adjusted_gas_vector.l1_gas
                        )
                    }),
                l1_data_gas: adjusted_gas_vector.l1_data_gas,
                l2_gas: GasAmount(0),
            },
        };

        // Blockifier does not put the actual fee into the receipt if `max_fee` in the
        // transaction was zero. In that case we have to compute the fee explicitly.
        let overall_fee = blockifier::fee::fee_utils::get_fee_by_gas_vector(
            block_context.block_info(),
            adjusted_gas_vector,
            &fee_type,
            tip,
        )
        .0;

        FeeEstimate {
            l1_gas_consumed: adjusted_gas_vector.l1_gas.0.into(),
            l1_gas_price: l1_gas_price.0.into(),
            l1_data_gas_consumed: adjusted_gas_vector.l1_data_gas.0.into(),
            l1_data_gas_price: l1_data_gas_price.0.into(),
            l2_gas_consumed: adjusted_gas_vector.l2_gas.0.into(),
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
pub enum TransactionExecutionInfo {
    Declare(DeclareTransactionExecutionInfo),
    DeployAccount(DeployAccountTransactionExecutionInfo),
    Invoke(InvokeTransactionExecutionInfo),
    L1Handler(L1HandlerTransactionExecutionInfo),
}

impl TransactionExecutionInfo {
    pub fn execution_status(&self) -> pathfinder_common::receipt::ExecutionStatus {
        use pathfinder_common::receipt::ExecutionStatus::{Reverted, Succeeded};
        match self {
            Self::Declare(_) | Self::DeployAccount(_) => Succeeded,
            Self::Invoke(ref i) => match &i.execute_invocation {
                RevertibleFunctionInvocation::FunctionInvocation(_) => Succeeded,
                RevertibleFunctionInvocation::RevertedReason(reason) => Reverted {
                    reason: reason.clone(),
                },
            },
            Self::L1Handler(ref h) => match &h.function_invocation {
                RevertibleFunctionInvocation::FunctionInvocation(_) => Succeeded,
                RevertibleFunctionInvocation::RevertedReason(reason) => Reverted {
                    reason: reason.clone(),
                },
            },
        }
    }

    pub fn execution_resources(
        &self,
    ) -> anyhow::Result<pathfinder_common::receipt::ExecutionResources> {
        match &self {
            Self::Declare(i) => &i.execution_resources,
            Self::DeployAccount(i) => &i.execution_resources,
            Self::Invoke(i) => &i.execution_resources,
            Self::L1Handler(i) => &i.execution_resources,
        }
        .try_into()
    }
}

#[derive(Debug, Clone)]
pub struct DeclareTransactionExecutionInfo {
    pub validate_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone)]
pub struct DeployAccountTransactionExecutionInfo {
    pub validate_invocation: Option<FunctionInvocation>,
    pub constructor_invocation: Option<FunctionInvocation>,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum RevertibleFunctionInvocation {
    FunctionInvocation(Option<FunctionInvocation>),
    RevertedReason(String),
}

#[derive(Debug, Clone)]
pub struct InvokeTransactionExecutionInfo {
    pub validate_invocation: Option<FunctionInvocation>,
    pub execute_invocation: RevertibleFunctionInvocation,
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    pub execution_resources: ExecutionResources,
}

#[derive(Debug, Clone)]
pub struct L1HandlerTransactionExecutionInfo {
    pub function_invocation: RevertibleFunctionInvocation,
    pub execution_resources: ExecutionResources,
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
                execution_info:
                    InvokeTransactionExecutionInfo {
                        execute_invocation:
                            RevertibleFunctionInvocation::RevertedReason(revert_reason),
                        ..
                    },
                ..
            }) => Some(revert_reason.as_str()),
            TransactionTrace::L1Handler(L1HandlerTransactionTrace {
                execution_info:
                    L1HandlerTransactionExecutionInfo {
                        function_invocation:
                            RevertibleFunctionInvocation::RevertedReason(revert_reason),
                        ..
                    },
                ..
            }) => Some(revert_reason.as_str()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeclareTransactionTrace {
    pub execution_info: DeclareTransactionExecutionInfo,
    pub state_diff: StateDiff,
}

#[derive(Debug, Clone)]
pub struct DeployAccountTransactionTrace {
    pub execution_info: DeployAccountTransactionExecutionInfo,
    pub state_diff: StateDiff,
}

#[derive(Debug, Clone)]
pub struct InvokeTransactionTrace {
    pub execution_info: InvokeTransactionExecutionInfo,
    pub state_diff: StateDiff,
}

#[derive(Debug, Clone)]
pub struct L1HandlerTransactionTrace {
    pub execution_info: L1HandlerTransactionExecutionInfo,
    pub state_diff: StateDiff,
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
    pub selector: Option<Felt>,
    pub call_type: Option<CallType>,
    pub caller_address: Felt,
    pub internal_calls: Vec<FunctionInvocation>,
    pub class_hash: Option<Felt>,
    pub entry_point_type: Option<EntryPointType>,
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

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct StorageDiff {
    pub key: StorageAddress,
    pub value: StorageValue,
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct DeployedContract {
    pub address: ContractAddress,
    pub class_hash: ClassHash,
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
pub struct DeclaredSierraClass {
    pub class_hash: SierraHash,
    pub compiled_class_hash: CasmHash,
}

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
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

impl TryFrom<&ExecutionResources> for pathfinder_common::receipt::ExecutionResources {
    type Error = anyhow::Error;

    fn try_from(x: &ExecutionResources) -> Result<Self, Self::Error> {
        Ok(Self {
            builtins: pathfinder_common::receipt::BuiltinCounters {
                output: 0, // TODO(validator)
                pedersen: x
                    .computation_resources
                    .poseidon_builtin_applications
                    .try_into()?,
                range_check: x
                    .computation_resources
                    .range_check_builtin_applications
                    .try_into()?,
                ecdsa: x
                    .computation_resources
                    .ecdsa_builtin_applications
                    .try_into()?,
                bitwise: x
                    .computation_resources
                    .bitwise_builtin_applications
                    .try_into()?,
                ec_op: x
                    .computation_resources
                    .ec_op_builtin_applications
                    .try_into()?,
                keccak: x
                    .computation_resources
                    .keccak_builtin_applications
                    .try_into()?,
                poseidon: x
                    .computation_resources
                    .poseidon_builtin_applications
                    .try_into()?,
                segment_arena: x.computation_resources.segment_arena_builtin.try_into()?,
                add_mod: 0,       // TODO(validator)
                mul_mod: 0,       // TODO(validator)
                range_check96: 0, // TODO(validator)
            },
            n_steps: x.computation_resources.steps.try_into()?,
            n_memory_holes: x.computation_resources.memory_holes.try_into()?,
            data_availability: pathfinder_common::receipt::L1Gas {
                l1_gas: x.data_availability.l1_gas,
                l1_data_gas: x.data_availability.l1_data_gas,
            },
            total_gas_consumed: pathfinder_common::receipt::L1Gas {
                l1_gas: x.l1_gas,
                l1_data_gas: x.l1_data_gas,
            },
            l2_gas: pathfinder_common::receipt::L2Gas(x.l2_gas),
        })
    }
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

impl FunctionInvocation {
    pub fn from_call_info(
        call_info: CallInfo,
        versioned_constants: &VersionedConstants,
        gas_vector_computation_mode: &GasVectorComputationMode,
    ) -> Self {
        let gas_consumed = call_info
            .summarize(versioned_constants)
            .to_partial_gas_vector(versioned_constants, gas_vector_computation_mode);

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
            selector: Some(call_info.call.entry_point_selector.0.into_felt()),
            call_type: Some(call_info.call.call_type.into()),
            caller_address: call_info.call.caller_address.0.key().into_felt(),
            internal_calls,
            class_hash: call_info
                .call
                .class_hash
                .map(|class_hash| class_hash.0.into_felt()),
            entry_point_type: Some(call_info.call.entry_point_type.into()),
            events,
            messages,
            result,
            computation_resources: call_info.resources.into(),
            execution_resources: InnerCallExecutionResources {
                l1_gas: gas_consumed.l1_gas.0.into(),
                l2_gas: gas_consumed.l2_gas.0.into(),
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

fn ordered_l2_to_l1_messages(call_info: &CallInfo) -> Vec<MsgToL1> {
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

impl From<StateDiff> for StateUpdateData {
    fn from(x: StateDiff) -> Self {
        let StateDiff {
            storage_diffs,
            deployed_contracts,
            deprecated_declared_classes,
            declared_classes,
            nonces,
            replaced_classes,
        } = x;

        let mut contract_updates = HashMap::new();
        let mut system_contract_updates = HashMap::new();

        storage_diffs.into_iter().for_each(|(address, storage)| {
            let storage = storage
                .into_iter()
                .map(|StorageDiff { key, value }| (key, value))
                .collect();

            if address.is_system_contract() {
                system_contract_updates.insert(address, SystemContractUpdate { storage });
            } else {
                contract_updates.insert(
                    address,
                    ContractUpdate {
                        storage,
                        class: None,
                        nonce: None,
                    },
                );
            }
        });

        deployed_contracts.into_iter().for_each(
            |DeployedContract {
                 address,
                 class_hash,
             }| {
                contract_updates.entry(address).or_default().class =
                    Some(ContractClassUpdate::Deploy(class_hash));
            },
        );

        nonces.into_iter().for_each(|(address, nonce)| {
            contract_updates.entry(address).or_default().nonce = Some(nonce);
        });

        replaced_classes.into_iter().for_each(
            |ReplacedClass {
                 contract_address,
                 class_hash,
             }| {
                contract_updates.entry(contract_address).or_default().class =
                    Some(ContractClassUpdate::Replace(class_hash));
            },
        );

        Self {
            contract_updates,
            system_contract_updates,
            declared_cairo_classes: deprecated_declared_classes,
            declared_sierra_classes: declared_classes
                .into_iter()
                .map(|c| (c.class_hash, c.compiled_class_hash))
                .collect(),
        }
    }
}

pub(crate) fn to_receipt_and_events(
    transaction_type: TransactionType,
    transaction_index: TransactionIndex,
    execution_info: blockifier::transaction::objects::TransactionExecutionInfo,
    versioned_constants: &VersionedConstants,
    gas_vector_computation_mode: &GasVectorComputationMode,
) -> anyhow::Result<(Receipt, Vec<pathfinder_common::event::Event>)> {
    let actual_fee = Fee(Felt::from_u128(execution_info.receipt.fee.0));
    let execution_info = to_execution_info(
        transaction_type,
        execution_info,
        versioned_constants,
        gas_vector_computation_mode,
    );

    // Maps to collect events and messages are ordered by the internal index of an
    // ordered but because indices of such items are not unique across
    // the entire block we must put duplicates and from comparing the order of
    // events/messages to the existing blocks we know that duplicated
    // indices are put at the end.
    let mut messages = BTreeMap::new();
    let mut events = BTreeMap::new();

    let execution_resources = execution_info.execution_resources()?;
    let execution_status = execution_info.execution_status();

    match execution_info {
        TransactionExecutionInfo::Declare(i) => {
            if let Some(fi) = i.validate_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
            if let Some(fi) = i.fee_transfer_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
        }
        TransactionExecutionInfo::DeployAccount(i) => {
            if let Some(fi) = i.validate_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
            if let Some(fi) = i.constructor_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
            if let Some(fi) = i.fee_transfer_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
        }
        TransactionExecutionInfo::Invoke(i) => {
            if let Some(fi) = i.validate_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
            if let RevertibleFunctionInvocation::FunctionInvocation(Some(fi)) = i.execute_invocation
            {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
            if let Some(fi) = i.fee_transfer_invocation {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
        }
        TransactionExecutionInfo::L1Handler(i) => {
            if let RevertibleFunctionInvocation::FunctionInvocation(Some(fi)) =
                i.function_invocation
            {
                collect_events_and_messages(fi, &mut events, &mut messages);
            }
        }
    };

    let l2_to_l1_messages = collect_items(messages);
    let events = collect_items(events);

    let receipt = Receipt {
        actual_fee,
        execution_resources,
        l2_to_l1_messages,
        execution_status,
        transaction_index,
    };

    Ok((receipt, events))
}

fn collect_events_and_messages(
    fi: FunctionInvocation,
    events: &mut BTreeMap<i64, VecDeque<pathfinder_common::event::Event>>,
    messages: &mut BTreeMap<usize, VecDeque<pathfinder_common::receipt::L2ToL1Message>>,
) {
    fi.events.into_iter().for_each(|e| {
        events
            .entry(e.order)
            .or_default()
            .push_back(pathfinder_common::event::Event {
                data: e.data.into_iter().map(EventData).collect(),
                from_address: fi.contract_address,
                keys: e.keys.into_iter().map(EventKey).collect(),
            });
    });
    fi.messages.into_iter().for_each(|m| {
        messages
            .entry(m.order)
            .or_default()
            .push_back(pathfinder_common::receipt::L2ToL1Message {
                from_address: ContractAddress(m.from_address),
                payload: m
                    .payload
                    .into_iter()
                    .map(L2ToL1MessagePayloadElem)
                    .collect(),
                to_address: ContractAddress(m.to_address),
            });
    });
    fi.internal_calls
        .into_iter()
        .for_each(|fi| collect_events_and_messages(fi, events, messages));
}

/// Collects all items, taking the first item from each key, one at a time,
/// until all items are consumed. Example: `{(0, [A, D]), (1, [B, E, G]), (2,
/// [C, F, H, I])} => [A, B, C, D, E, F, G, H, I]`
fn collect_items<Idx: Copy + Ord, Item>(mut messages: BTreeMap<Idx, VecDeque<Item>>) -> Vec<Item> {
    let mut items = Vec::with_capacity(messages.values().flatten().count());
    let mut keys = Vec::with_capacity(messages.len());

    while !messages.is_empty() {
        messages.keys().for_each(|k| keys.push(*k));

        for key in &keys {
            let messages_with_same_key = messages.get_mut(key).expect("Key exists");
            items.push(messages_with_same_key.pop_front().expect("Not empty"));
            if messages_with_same_key.is_empty() {
                messages.remove(key);
            }
        }

        keys.clear();
    }
    items
}

pub(crate) enum TransactionType {
    Declare,
    DeployAccount,
    Invoke,
    L1Handler,
}

pub(crate) fn transaction_type(transaction: &Transaction) -> TransactionType {
    match transaction {
        Transaction::Account(tx) => match tx.tx {
            starknet_api::executable_transaction::AccountTransaction::Declare(_) => {
                TransactionType::Declare
            }
            starknet_api::executable_transaction::AccountTransaction::DeployAccount(_) => {
                TransactionType::DeployAccount
            }
            starknet_api::executable_transaction::AccountTransaction::Invoke(_) => {
                TransactionType::Invoke
            }
        },
        Transaction::L1Handler(_) => TransactionType::L1Handler,
    }
}

pub(crate) fn transaction_declared_deprecated_class(
    transaction: &Transaction,
) -> Option<ClassHash> {
    match transaction {
        Transaction::Account(outer) => match &outer.tx {
            starknet_api::executable_transaction::AccountTransaction::Declare(inner) => {
                match inner.tx {
                    starknet_api::transaction::DeclareTransaction::V0(_)
                    | starknet_api::transaction::DeclareTransaction::V1(_) => {
                        Some(ClassHash(inner.class_hash().0.into_felt()))
                    }
                    starknet_api::transaction::DeclareTransaction::V2(_)
                    | starknet_api::transaction::DeclareTransaction::V3(_) => None,
                }
            }
            _ => None,
        },
        _ => None,
    }
}

pub(crate) fn to_state_diff<S: StorageAdapter + Clone>(
    state_maps: StateMaps,
    initial_state: PathfinderExecutionState<S>,
    old_declared_contracts: impl Iterator<Item = ClassHash>,
) -> Result<StateDiff, StateError> {
    let mut deployed_contracts = Vec::new();
    let mut replaced_classes = Vec::new();

    // We need to check the previous class hash for a contract to decide if it's a
    // deployed contract or a replaced class.
    for (address, class_hash) in state_maps.class_hashes {
        let is_deployed = initial_state
            .get_class_hash_at(address)?
            .0
            .into_felt()
            .is_zero();
        if is_deployed {
            deployed_contracts.push(DeployedContract {
                address: ContractAddress::new_or_panic(address.0.key().into_felt()),
                class_hash: ClassHash(class_hash.0.into_felt()),
            });
        } else {
            replaced_classes.push(ReplacedClass {
                contract_address: ContractAddress::new_or_panic(address.0.key().into_felt()),
                class_hash: ClassHash(class_hash.0.into_felt()),
            });
        }
    }

    let mut storage_diffs: BTreeMap<_, _> = Default::default();
    for ((address, key), value) in state_maps.storage {
        storage_diffs
            .entry(ContractAddress::new_or_panic(address.0.key().into_felt()))
            .and_modify(|map: &mut BTreeMap<StorageAddress, StorageValue>| {
                map.insert(
                    StorageAddress::new_or_panic(key.0.key().into_felt()),
                    StorageValue(value.into_felt()),
                );
            })
            .or_insert_with(|| {
                let mut map = BTreeMap::new();
                map.insert(
                    StorageAddress::new_or_panic(key.0.key().into_felt()),
                    StorageValue(value.into_felt()),
                );
                map
            });
    }
    let storage_diffs: BTreeMap<_, Vec<StorageDiff>> = storage_diffs
        .into_iter()
        .map(|(address, diffs)| {
            (
                address,
                diffs
                    .into_iter()
                    .map(|(key, value)| StorageDiff { key, value })
                    .collect(),
            )
        })
        .collect();

    Ok(StateDiff {
        storage_diffs,
        deployed_contracts,
        // This info is not present in the state diff, so we need to pass it separately.
        deprecated_declared_classes: old_declared_contracts.collect(),
        declared_classes: state_maps
            .compiled_class_hashes
            .into_iter()
            .map(|(class_hash, compiled_class_hash)| DeclaredSierraClass {
                class_hash: SierraHash(class_hash.0.into_felt()),
                compiled_class_hash: CasmHash(compiled_class_hash.0.into_felt()),
            })
            .collect(),
        nonces: state_maps
            .nonces
            .into_iter()
            .map(|(address, nonce)| {
                (
                    ContractAddress::new_or_panic(address.0.key().into_felt()),
                    ContractNonce(nonce.0.into_felt()),
                )
            })
            .collect(),
        replaced_classes,
    })
}

pub(crate) fn to_execution_info(
    transaction_type: TransactionType,
    execution_info: blockifier::transaction::objects::TransactionExecutionInfo,
    versioned_constants: &VersionedConstants,
    gas_vector_computation_mode: &GasVectorComputationMode,
) -> TransactionExecutionInfo {
    let validate_invocation = execution_info.validate_call_info.map(|call_info| {
        FunctionInvocation::from_call_info(
            call_info,
            versioned_constants,
            gas_vector_computation_mode,
        )
    });
    let maybe_function_invocation = execution_info.execute_call_info.map(|call_info| {
        FunctionInvocation::from_call_info(
            call_info,
            versioned_constants,
            gas_vector_computation_mode,
        )
    });
    let fee_transfer_invocation = execution_info.fee_transfer_call_info.map(|call_info| {
        FunctionInvocation::from_call_info(
            call_info,
            versioned_constants,
            gas_vector_computation_mode,
        )
    });

    let computation_resources = validate_invocation
        .as_ref()
        .map(|i: &FunctionInvocation| i.computation_resources.clone())
        .unwrap_or_default()
        + maybe_function_invocation
            .as_ref()
            .map(|i: &FunctionInvocation| i.computation_resources.clone())
            .unwrap_or_default()
        + fee_transfer_invocation
            .as_ref()
            .map(|i: &FunctionInvocation| i.computation_resources.clone())
            .unwrap_or_default();
    let data_availability = DataAvailabilityResources {
        l1_gas: execution_info.receipt.da_gas.l1_gas.0.into(),
        l1_data_gas: execution_info.receipt.da_gas.l1_data_gas.0.into(),
    };
    let execution_resources = ExecutionResources {
        computation_resources,
        data_availability,
        l1_gas: execution_info.receipt.gas.l1_gas.0.into(),
        l1_data_gas: execution_info.receipt.gas.l1_data_gas.0.into(),
        l2_gas: execution_info.receipt.gas.l2_gas.0.into(),
    };

    match transaction_type {
        TransactionType::Declare => {
            TransactionExecutionInfo::Declare(DeclareTransactionExecutionInfo {
                validate_invocation,
                fee_transfer_invocation,
                execution_resources,
            })
        }
        TransactionType::DeployAccount => {
            TransactionExecutionInfo::DeployAccount(DeployAccountTransactionExecutionInfo {
                validate_invocation,
                constructor_invocation: maybe_function_invocation,
                fee_transfer_invocation,
                execution_resources,
            })
        }
        TransactionType::Invoke => {
            TransactionExecutionInfo::Invoke(InvokeTransactionExecutionInfo {
                validate_invocation,
                execute_invocation: if let Some(reason) = execution_info.revert_error {
                    RevertibleFunctionInvocation::RevertedReason(reason.to_string())
                } else {
                    RevertibleFunctionInvocation::FunctionInvocation(maybe_function_invocation)
                },
                fee_transfer_invocation,
                execution_resources,
            })
        }
        TransactionType::L1Handler => {
            TransactionExecutionInfo::L1Handler(L1HandlerTransactionExecutionInfo {
                function_invocation: if let Some(reason) = execution_info.revert_error {
                    RevertibleFunctionInvocation::RevertedReason(reason.to_string())
                } else {
                    RevertibleFunctionInvocation::FunctionInvocation(maybe_function_invocation)
                },
                execution_resources,
            })
        }
    }
}

pub fn to_starknet_api_transaction(
    variant: TransactionVariant,
) -> anyhow::Result<starknet_api::transaction::Transaction> {
    use starknet_api::transaction::fields::{ContractAddressSalt, Fee, Tip};

    match variant {
        TransactionVariant::DeclareV0(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                max_fee: Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V0(tx),
            ))
        }
        TransactionVariant::DeclareV1(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                max_fee: Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V1(tx),
            ))
        }
        TransactionVariant::DeclareV2(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV2 {
                max_fee: Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                compiled_class_hash: starknet_api::core::CompiledClassHash(
                    tx.compiled_class_hash.0.into_starkfelt(),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V2(tx),
            ))
        }
        TransactionVariant::DeclareV3(tx) => {
            let tx = starknet_api::transaction::DeclareTransactionV3 {
                resource_bounds: to_starknet_api_resource_bounds(tx.resource_bounds)?,
                tip: Tip(tx.tip.0),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                compiled_class_hash: starknet_api::core::CompiledClassHash(
                    tx.compiled_class_hash.0.into_starkfelt(),
                ),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                nonce_data_availability_mode: tx
                    .nonce_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                fee_data_availability_mode: tx
                    .fee_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                paymaster_data: PaymasterData(
                    tx.paymaster_data
                        .iter()
                        .map(|p| p.0.into_starkfelt())
                        .collect(),
                ),
                account_deployment_data: AccountDeploymentData(
                    tx.account_deployment_data
                        .iter()
                        .map(|a| a.0.into_starkfelt())
                        .collect(),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Declare(
                starknet_api::transaction::DeclareTransaction::V3(tx),
            ))
        }
        TransactionVariant::DeployV0(_) | TransactionVariant::DeployV1(_) => {
            anyhow::bail!("Deploy transactions are not yet supported in blockifier")
        }
        TransactionVariant::DeployAccountV1(tx) => {
            let tx = starknet_api::transaction::DeployAccountTransaction::V1(
                starknet_api::transaction::DeployAccountTransactionV1 {
                    max_fee: Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: TransactionSignature(Arc::new(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    )),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),

                    contract_address_salt: ContractAddressSalt(
                        tx.contract_address_salt.0.into_starkfelt(),
                    ),
                    constructor_calldata: Calldata(std::sync::Arc::new(
                        tx.constructor_calldata
                            .iter()
                            .map(|c| c.0.into_starkfelt())
                            .collect(),
                    )),
                },
            );

            Ok(starknet_api::transaction::Transaction::DeployAccount(tx))
        }
        TransactionVariant::DeployAccountV3(tx) => {
            let resource_bounds = to_starknet_api_resource_bounds(tx.resource_bounds)?;

            let tx = starknet_api::transaction::DeployAccountTransaction::V3(
                starknet_api::transaction::DeployAccountTransactionV3 {
                    resource_bounds,
                    tip: Tip(tx.tip.0),
                    signature: TransactionSignature(Arc::new(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    )),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                    contract_address_salt: ContractAddressSalt(
                        tx.contract_address_salt.0.into_starkfelt(),
                    ),
                    constructor_calldata: Calldata(std::sync::Arc::new(
                        tx.constructor_calldata
                            .iter()
                            .map(|c| c.0.into_starkfelt())
                            .collect(),
                    )),
                    nonce_data_availability_mode: tx
                        .nonce_data_availability_mode
                        .into_starkfelt()
                        .try_into()?,
                    fee_data_availability_mode: tx
                        .fee_data_availability_mode
                        .into_starkfelt()
                        .try_into()?,
                    paymaster_data: PaymasterData(
                        tx.paymaster_data
                            .iter()
                            .map(|p| p.0.into_starkfelt())
                            .collect(),
                    ),
                },
            );

            Ok(starknet_api::transaction::Transaction::DeployAccount(tx))
        }
        TransactionVariant::InvokeV0(tx) => {
            let tx = starknet_api::transaction::InvokeTransactionV0 {
                // TODO: maybe we should store tx.max_fee as u128 internally?
                max_fee: Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                contract_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                entry_point_selector: starknet_api::core::EntryPointSelector(
                    tx.entry_point_selector.0.into_starkfelt(),
                ),
                calldata: Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
            };

            Ok(starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V0(tx),
            ))
        }
        TransactionVariant::InvokeV1(tx) => {
            let tx = starknet_api::transaction::InvokeTransactionV1 {
                // TODO: maybe we should store tx.max_fee as u128 internally?
                max_fee: Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                calldata: Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
            };

            Ok(starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V1(tx),
            ))
        }
        TransactionVariant::InvokeV3(tx) => {
            let resource_bounds = to_starknet_api_resource_bounds(tx.resource_bounds)?;

            let tx = starknet_api::transaction::InvokeTransactionV3 {
                resource_bounds,
                tip: Tip(tx.tip.0),
                signature: TransactionSignature(Arc::new(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                )),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                sender_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                calldata: Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
                nonce_data_availability_mode: tx
                    .nonce_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                fee_data_availability_mode: tx
                    .fee_data_availability_mode
                    .into_starkfelt()
                    .try_into()?,
                paymaster_data: PaymasterData(
                    tx.paymaster_data
                        .iter()
                        .map(|p| p.0.into_starkfelt())
                        .collect(),
                ),
                account_deployment_data: AccountDeploymentData(
                    tx.account_deployment_data
                        .iter()
                        .map(|a| a.0.into_starkfelt())
                        .collect(),
                ),
            };

            Ok(starknet_api::transaction::Transaction::Invoke(
                starknet_api::transaction::InvokeTransaction::V3(tx),
            ))
        }
        TransactionVariant::L1Handler(tx) => {
            let tx = starknet_api::transaction::L1HandlerTransaction {
                version: starknet_api::transaction::TransactionVersion::ZERO,
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                contract_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                        .expect("No contract address overflow expected"),
                ),
                entry_point_selector: starknet_api::core::EntryPointSelector(
                    tx.entry_point_selector.0.into_starkfelt(),
                ),
                calldata: Calldata(std::sync::Arc::new(
                    tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                )),
            };

            Ok(starknet_api::transaction::Transaction::L1Handler(tx))
        }
    }
}

fn to_starknet_api_resource_bounds(
    r: pathfinder_common::transaction::ResourceBounds,
) -> Result<ValidResourceBounds, starknet_api::StarknetApiError> {
    use starknet_api::block::GasPrice;
    use starknet_api::execution_resources::GasAmount;
    use starknet_api::transaction::fields::ResourceBounds;

    let valid_resource_bounds = match r.l1_data_gas {
        Some(l1_data_gas) => ValidResourceBounds::AllResources(AllResourceBounds {
            l1_gas: ResourceBounds {
                max_amount: GasAmount(r.l1_gas.max_amount.0),
                max_price_per_unit: GasPrice(r.l1_gas.max_price_per_unit.0),
            },
            l2_gas: ResourceBounds {
                max_amount: GasAmount(r.l2_gas.max_amount.0),
                max_price_per_unit: GasPrice(r.l2_gas.max_price_per_unit.0),
            },
            l1_data_gas: ResourceBounds {
                max_amount: GasAmount(l1_data_gas.max_amount.0),
                max_price_per_unit: GasPrice(l1_data_gas.max_price_per_unit.0),
            },
        }),
        None => ValidResourceBounds::L1Gas(ResourceBounds {
            max_amount: GasAmount(r.l1_gas.max_amount.0),
            max_price_per_unit: GasPrice(r.l1_gas.max_price_per_unit.0),
        }),
    };

    Ok(valid_resource_bounds)
}
