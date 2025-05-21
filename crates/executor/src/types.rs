use std::collections::{BTreeMap, HashSet};

use anyhow::Context;
use blockifier::execution::call_info::OrderedL2ToL1Message;
use pathfinder_common::prelude::*;
use pathfinder_common::receipt::Receipt;
use pathfinder_crypto::Felt;
use starknet_api::block::FeeType;
use starknet_api::execution_resources::GasVector;

use super::felt::IntoFelt;

pub const ETH_TO_WEI_RATE: u128 = 1_000_000_000_000_000_000;

// TODO FIXME probably much better in pathfinder_common
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
    pub fn try_from_proposal(
        height: u64,
        timestamp: u64,
        builder: SequencerAddress,
        l1_da_mode: L1DataAvailabilityMode,
        l2_gas_price_fri: u128,
        l1_gas_price_wei: u128,
        l1_data_gas_price_wei: u128,
        // TODO FIXME ignored for the time being, see comment below
        eth_to_fri_rate: u128,
        starknet_version: StarknetVersion,
        // TODO FIXME
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
        // TODO FIXME
        // let strk_l1_gas_price = GasPrice(wei_to_fri(l1_gas_price_wei));
        let strk_l1_gas_price = GasPrice(workaround_l1_gas_price_fri);
        let eth_l1_data_gas_price = GasPrice(l1_data_gas_price_wei);
        // TODO FIXME
        // let strk_l1_data_gas_price = GasPrice(wei_to_fri(l1_data_gas_price_wei));
        let strk_l1_data_gas_price = GasPrice(workaround_l1_data_gas_price_fri);
        // TODO FIXME
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
        block_info: &starknet_api::block::BlockInfo,
        fee_type: FeeType,
        minimal_gas_vector: &Option<GasVector>,
    ) -> FeeEstimate {
        tracing::trace!(?gas_vector, "Transaction resources");
        let gas_prices = block_info.gas_prices.gas_price_vector(&fee_type);
        let l1_gas_price = gas_prices.l1_gas_price.get();
        let l1_data_gas_price = gas_prices.l1_data_gas_price.get();
        let l2_gas_price = gas_prices.l2_gas_price.get();

        let minimal_gas_vector = minimal_gas_vector.unwrap_or_default();

        let l1_gas_consumed = gas_vector.l1_gas.max(minimal_gas_vector.l1_gas);
        let l1_data_gas_consumed = gas_vector.l1_data_gas.max(minimal_gas_vector.l1_data_gas);
        let l2_gas_consumed = gas_vector.l2_gas.max(minimal_gas_vector.l2_gas);

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

    pub fn state_diff(&self) -> &StateDiff {
        self.trace.state_diff()
    }

    pub fn execution_status(&self) -> pathfinder_common::receipt::ExecutionStatus {
        use pathfinder_common::receipt::ExecutionStatus::{Reverted, Succeeded};
        match self.trace {
            TransactionTrace::Declare(_)
            | TransactionTrace::DeployAccount(_)
            | TransactionTrace::L1Handler(_) => Succeeded,
            TransactionTrace::Invoke(ref t) => match &t.execute_invocation {
                ExecuteInvocation::FunctionInvocation(_) => Succeeded,
                ExecuteInvocation::RevertedReason(reason) => Reverted {
                    reason: reason.clone(),
                },
            },
        }
    }

    pub fn execution_resources(
        &self,
    ) -> anyhow::Result<pathfinder_common::receipt::ExecutionResources> {
        match &self.trace {
            TransactionTrace::Declare(t) => &t.execution_resources,
            TransactionTrace::DeployAccount(t) => &t.execution_resources,
            TransactionTrace::Invoke(t) => &t.execution_resources,
            TransactionTrace::L1Handler(t) => &t.execution_resources,
        }
        .try_into()
    }
}

// TODO FIXME leave only one version either via ref or consuming
fn collect_events_and_messages(
    fi: &FunctionInvocation,
    events: &mut BTreeMap<i64, pathfinder_common::event::Event>,
    messages: &mut BTreeMap<usize, pathfinder_common::receipt::L2ToL1Message>,
) {
    fi.events.iter().for_each(|e| {
        events.insert(
            e.order,
            pathfinder_common::event::Event {
                data: e.data.iter().map(|d| EventData(*d)).collect(),
                from_address: fi.contract_address,
                keys: e.keys.iter().map(|k| EventKey(*k)).collect(),
            },
        );
    });
    fi.messages.iter().for_each(|m| {
        messages.insert(
            m.order,
            pathfinder_common::receipt::L2ToL1Message {
                from_address: ContractAddress(m.from_address),
                payload: m
                    .payload
                    .iter()
                    .map(|p| L2ToL1MessagePayloadElem(*p))
                    .collect(),
                to_address: ContractAddress(m.to_address),
            },
        );
    });
    fi.internal_calls
        .iter()
        .for_each(|fi| collect_events_and_messages(fi, events, messages));
}

// TODO FIXME leave only one version either via ref or consuming
fn collect_events_and_messages2(
    fi: FunctionInvocation,
    events: &mut BTreeMap<i64, pathfinder_common::event::Event>,
    messages: &mut BTreeMap<usize, pathfinder_common::receipt::L2ToL1Message>,
) {
    fi.events.into_iter().for_each(|e| {
        events.insert(
            e.order,
            pathfinder_common::event::Event {
                data: e.data.into_iter().map(EventData).collect(),
                from_address: fi.contract_address,
                keys: e.keys.into_iter().map(EventKey).collect(),
            },
        );
    });
    fi.messages.into_iter().for_each(|m| {
        messages.insert(
            m.order,
            pathfinder_common::receipt::L2ToL1Message {
                from_address: ContractAddress(m.from_address),
                payload: m
                    .payload
                    .into_iter()
                    .map(L2ToL1MessagePayloadElem)
                    .collect(),
                to_address: ContractAddress(m.to_address),
            },
        );
    });
    fi.internal_calls
        .iter()
        .for_each(|fi| collect_events_and_messages(fi, events, messages));
}

/*
// TODO FIXME common::Receipt-s shouldn't hold transaction hashes nor
// transaction indices, keep only one conversion (ie. from self or &self)
impl TryFrom<&TransactionSimulation> for (Receipt, Vec<pathfinder_common::event::Event>) {
    type Error = anyhow::Error;

    fn try_from(x: &TransactionSimulation) -> Result<Self, Self::Error> {
        let mut messages = BTreeMap::new();
        let mut events = BTreeMap::new();

        match &x.trace {
            TransactionTrace::Declare(t) => {
                t.validate_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
                t.fee_transfer_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
            }
            TransactionTrace::DeployAccount(t) => {
                t.validate_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
                t.constructor_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
                t.fee_transfer_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
            }
            TransactionTrace::Invoke(t) => {
                t.validate_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
                if let ExecuteInvocation::FunctionInvocation(Some(fi)) = &t.execute_invocation {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                }
                t.fee_transfer_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
            }
            TransactionTrace::L1Handler(t) => {
                t.function_invocation.as_ref().map(|fi| {
                    collect_events_and_messages(fi, &mut events, &mut messages);
                });
            }
        };

        let mut buf = [0u8; 32];
        x.fee_estimation.overall_fee.to_big_endian(&mut buf);
        let actual_fee = Fee(Felt::from_be_bytes(buf)?);

        let receipt = Receipt {
            actual_fee,
            execution_resources: x.execution_resources()?,
            l2_to_l1_messages: messages.into_values().collect(),
            execution_status: x.execution_status(),
            transaction_hash: TransactionHash::ZERO, // TODO FIXME
            transaction_index: TransactionIndex::new_or_panic(0), // TODO FIXME
        };

        Ok((receipt, events.into_values().collect()))
    }
}
*/

// TODO FIXME common::Receipt-s shouldn't hold transaction hashes nor
// transaction indices, keep only one conversion (ie. from self or &self)
impl TryFrom<TransactionSimulation> for (Receipt, Vec<pathfinder_common::event::Event>) {
    type Error = anyhow::Error;

    fn try_from(x: TransactionSimulation) -> Result<Self, Self::Error> {
        let mut messages = BTreeMap::new();
        let mut events = BTreeMap::new();

        let execution_resources = x.execution_resources()?;
        let execution_status = x.execution_status();
        match x.trace {
            TransactionTrace::Declare(t) => {
                t.validate_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
                t.fee_transfer_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
            }
            TransactionTrace::DeployAccount(t) => {
                t.validate_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
                t.constructor_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
                t.fee_transfer_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
            }
            TransactionTrace::Invoke(t) => {
                t.validate_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
                if let ExecuteInvocation::FunctionInvocation(Some(fi)) = t.execute_invocation {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                }
                t.fee_transfer_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
            }
            TransactionTrace::L1Handler(t) => {
                t.function_invocation.map(|fi| {
                    collect_events_and_messages2(fi, &mut events, &mut messages);
                });
            }
        };

        let mut buf = [0u8; 32];
        x.fee_estimation.overall_fee.to_big_endian(&mut buf);
        let actual_fee = Fee(Felt::from_be_bytes(buf)?);

        let receipt = Receipt {
            actual_fee,
            execution_resources,
            l2_to_l1_messages: messages.into_values().collect(),
            execution_status,
            transaction_hash: TransactionHash::ZERO, // TODO FIXME
            transaction_index: TransactionIndex::new_or_panic(0), // TODO FIXME
        };

        Ok((receipt, events.into_values().collect()))
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

    fn state_diff(&self) -> &StateDiff {
        match self {
            TransactionTrace::Declare(trace) => &trace.state_diff,
            TransactionTrace::DeployAccount(trace) => &trace.state_diff,
            TransactionTrace::Invoke(trace) => &trace.state_diff,
            TransactionTrace::L1Handler(trace) => &trace.state_diff,
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
                output: 0, // TODO FIXME
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
                add_mod: 0,       // TODO FIXME
                mul_mod: 0,       // TODO FIXME
                range_check96: 0, // TODO FIXME
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
        call_info: blockifier::execution::call_info::CallInfo,
        versioned_constants: &blockifier::versioned_constants::VersionedConstants,
        gas_vector_computation_mode: &starknet_api::transaction::fields::GasVectorComputationMode,
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

impl From<StateUpdate> for StateDiff {
    fn from(value: StateUpdate) -> Self {
        let StateUpdate {
            block_hash: _,
            parent_state_commitment: _,
            state_commitment: _,
            contract_updates,
            system_contract_updates,
            declared_cairo_classes,
            declared_sierra_classes,
        } = value;

        let storage_diffs = contract_updates
            .iter()
            .map(|(contract_address, x)| (contract_address, x.storage.clone()))
            .chain(
                system_contract_updates
                    .iter()
                    .map(|(contract_address, x)| (contract_address, x.storage.clone())),
            )
            .map(|(contract_address, storage)| {
                (
                    *contract_address,
                    storage
                        .into_iter()
                        .map(|(key, value)| StorageDiff { key, value })
                        .collect(),
                )
            })
            .collect();

        Self {
            storage_diffs,
            deployed_contracts: Default::default(),
            declared_classes: Default::default(),
            nonces: Default::default(),
            replaced_classes: Default::default(),
            deprecated_declared_classes: Default::default(),
        }
    }
}
