use pathfinder_common::{CallParam, EntryPoint};
use pathfinder_crypto::Felt;
use pathfinder_executor::types::TransactionSimulation;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use starknet_gateway_types::trace as gateway_trace;

use crate::felt::RpcFelt;
use crate::method::call::FunctionCall;
use crate::method::get_state_update::types::StateDiff;
use crate::types::PriceUnit;

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub struct SimulationFlags(pub Vec<SimulationFlag>);

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FeeEstimate {
    /// The Ethereum gas cost of the transaction
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    /// The gas price (in gwei) that was used in the cost estimation (input
    /// to fee estimation)
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
    /// The Ethereum data gas cost of the transaction
    #[serde_as(as = "Option<pathfinder_serde::U256AsHexStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_gas_consumed: Option<primitive_types::U256>,
    /// The data gas price (in gwei) that was used in the cost estimation
    /// (input to fee estimation)
    #[serde_as(as = "Option<pathfinder_serde::U256AsHexStr>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_gas_price: Option<primitive_types::U256>,
    /// The estimated fee for the transaction (in gwei), product of
    /// gas_consumed and gas_price
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub overall_fee: primitive_types::U256,
    pub unit: PriceUnit,
}

impl FeeEstimate {
    pub fn with_v06_format(&mut self) {
        self.data_gas_consumed = None;
        self.data_gas_price = None;
    }
}

impl From<pathfinder_executor::types::FeeEstimate> for FeeEstimate {
    fn from(value: pathfinder_executor::types::FeeEstimate) -> Self {
        Self {
            gas_consumed: value.l1_gas_consumed,
            gas_price: value.l1_gas_price,
            data_gas_consumed: Some(value.l1_data_gas_consumed),
            data_gas_price: Some(value.l1_data_gas_price),
            overall_fee: value.overall_fee,
            unit: value.unit.into(),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum SimulationFlag {
    #[serde(rename = "SKIP_FEE_CHARGE")]
    SkipFeeCharge,
    #[serde(rename = "SKIP_VALIDATE")]
    SkipValidate,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub enum CallType {
    #[serde(rename = "CALL")]
    Call,
    #[serde(rename = "LIBRARY_CALL")]
    _LibraryCall,
    #[serde(rename = "DELEGATE")]
    Delegate,
}

impl From<pathfinder_executor::types::CallType> for CallType {
    fn from(value: pathfinder_executor::types::CallType) -> Self {
        use pathfinder_executor::types::CallType::*;
        match value {
            Call => Self::Call,
            Delegate => Self::Delegate,
        }
    }
}

#[serde_with::serde_as]
#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct FunctionInvocation {
    #[serde(default)]
    pub call_type: CallType,
    #[serde(default)]
    #[serde_as(as = "RpcFelt")]
    pub caller_address: Felt,
    #[serde(default)]
    pub calls: Vec<FunctionInvocation>,
    #[serde(default)]
    #[serde_as(as = "Option<RpcFelt>")]
    pub class_hash: Option<Felt>,
    #[serde(default)]
    pub entry_point_type: EntryPointType,
    #[serde(default)]
    pub events: Vec<OrderedEvent>,
    #[serde(flatten)]
    pub function_call: FunctionCall,
    #[serde(default)]
    pub messages: Vec<OrderedMsgToL1>,
    #[serde(default)]
    #[serde_as(as = "Vec<RpcFelt>")]
    pub result: Vec<Felt>,
    pub execution_resources: ComputationResources,
}

impl From<pathfinder_executor::types::FunctionInvocation> for FunctionInvocation {
    fn from(fi: pathfinder_executor::types::FunctionInvocation) -> Self {
        Self {
            call_type: fi.call_type.into(),
            caller_address: fi.caller_address,
            calls: fi.internal_calls.into_iter().map(Into::into).collect(),
            class_hash: fi.class_hash,
            entry_point_type: fi.entry_point_type.into(),
            events: fi.events.into_iter().map(Into::into).collect(),
            function_call: FunctionCall {
                contract_address: fi.contract_address,
                entry_point_selector: EntryPoint(fi.selector),
                calldata: fi.calldata.into_iter().map(CallParam).collect(),
            },
            messages: fi.messages.into_iter().map(Into::into).collect(),
            result: fi.result.into_iter().map(Into::into).collect(),
            execution_resources: fi.computation_resources.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub enum EntryPointType {
    #[serde(rename = "CONSTRUCTOR")]
    Constructor,
    #[serde(rename = "EXTERNAL")]
    External,
    #[serde(rename = "L1_HANDLER")]
    L1Handler,
}

impl From<pathfinder_executor::types::EntryPointType> for EntryPointType {
    fn from(value: pathfinder_executor::types::EntryPointType) -> Self {
        use pathfinder_executor::types::EntryPointType::*;
        match value {
            Constructor => Self::Constructor,
            External => Self::External,
            L1Handler => Self::L1Handler,
        }
    }
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct OrderedMsgToL1 {
    pub order: usize,
    #[serde_as(as = "Vec<RpcFelt>")]
    pub payload: Vec<Felt>,
    #[serde_as(as = "RpcFelt")]
    pub to_address: Felt,
    #[serde_as(as = "RpcFelt")]
    pub from_address: Felt,
}

impl From<pathfinder_executor::types::MsgToL1> for OrderedMsgToL1 {
    fn from(value: pathfinder_executor::types::MsgToL1) -> Self {
        Self {
            order: value.order,
            payload: value.payload,
            to_address: value.to_address,
            from_address: value.from_address,
        }
    }
}

#[serde_with::serde_as]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct OrderedEvent {
    pub order: i64,
    #[serde_as(as = "Vec<RpcFelt>")]
    pub data: Vec<Felt>,
    #[serde_as(as = "Vec<RpcFelt>")]
    pub keys: Vec<Felt>,
}

impl From<pathfinder_executor::types::Event> for OrderedEvent {
    fn from(value: pathfinder_executor::types::Event) -> Self {
        Self {
            order: value.order,
            data: value.data,
            keys: value.keys,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ComputationResources {
    pub steps: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub memory_holes: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub range_check_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub pedersen_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub poseidon_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub ec_op_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub ecdsa_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub bitwise_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub keccak_builtin_applications: usize,
    #[serde(skip_serializing_if = "builtin_applications_is_zero")]
    pub segment_arena_builtin: usize,
}

fn builtin_applications_is_zero(n: &usize) -> bool {
    *n == 0
}

impl From<pathfinder_executor::types::ComputationResources> for ComputationResources {
    fn from(value: pathfinder_executor::types::ComputationResources) -> Self {
        Self {
            steps: value.steps,
            memory_holes: value.memory_holes,
            range_check_builtin_applications: value.range_check_builtin_applications,
            pedersen_builtin_applications: value.pedersen_builtin_applications,
            poseidon_builtin_applications: value.poseidon_builtin_applications,
            ec_op_builtin_applications: value.ec_op_builtin_applications,
            ecdsa_builtin_applications: value.ecdsa_builtin_applications,
            bitwise_builtin_applications: value.bitwise_builtin_applications,
            keccak_builtin_applications: value.keccak_builtin_applications,
            segment_arena_builtin: value.segment_arena_builtin,
        }
    }
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

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct DataAvailabilityResources {
    pub l1_gas: u128,
    pub l1_data_gas: u128,
}

impl From<pathfinder_executor::types::DataAvailabilityResources> for DataAvailabilityResources {
    fn from(value: pathfinder_executor::types::DataAvailabilityResources) -> Self {
        Self {
            l1_gas: value.l1_gas,
            l1_data_gas: value.l1_data_gas,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
pub struct ExecutionResources {
    #[serde(flatten)]
    pub computation_resources: ComputationResources,
    pub data_availability: DataAvailabilityResources,
}

impl From<pathfinder_executor::types::ExecutionResources> for ExecutionResources {
    fn from(value: pathfinder_executor::types::ExecutionResources) -> Self {
        Self {
            computation_resources: value.computation_resources.into(),
            data_availability: value.data_availability.into(),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct DeclareTxnTrace {
    #[serde(default)]
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    #[serde(default)]
    pub validate_invocation: Option<FunctionInvocation>,
    pub state_diff: Option<StateDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_resources: Option<ExecutionResources>,
}

impl DeclareTxnTrace {
    pub fn with_v06_format(&mut self) {
        self.execution_resources = None
    }
}

impl From<pathfinder_executor::types::DeclareTransactionTrace> for DeclareTxnTrace {
    fn from(trace: pathfinder_executor::types::DeclareTransactionTrace) -> Self {
        Self {
            fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            validate_invocation: trace.validate_invocation.map(Into::into),
            state_diff: Some(trace.state_diff.into()),
            execution_resources: Some(trace.execution_resources.into()),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct DeployAccountTxnTrace {
    #[serde(default)]
    pub constructor_invocation: FunctionInvocation,
    #[serde(default)]
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    #[serde(default)]
    pub validate_invocation: Option<FunctionInvocation>,
    pub state_diff: Option<StateDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_resources: Option<ExecutionResources>,
}

impl DeployAccountTxnTrace {
    pub fn with_v06_format(&mut self) {
        self.execution_resources = None
    }
}

impl TryFrom<pathfinder_executor::types::DeployAccountTransactionTrace> for DeployAccountTxnTrace {
    type Error = pathfinder_executor::TransactionExecutionError;

    fn try_from(
        trace: pathfinder_executor::types::DeployAccountTransactionTrace,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            constructor_invocation: trace
                .constructor_invocation
                .ok_or_else(|| {
                    Self::Error::Custom(anyhow::anyhow!("Missing constructor_invocation in trace"))
                })?
                .into(),
            fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            validate_invocation: trace.validate_invocation.map(Into::into),
            state_diff: Some(trace.state_diff.into()),
            execution_resources: Some(trace.execution_resources.into()),
        })
    }
}

#[derive(Clone, Debug, Default, Serialize, Eq, PartialEq)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ExecuteInvocation {
    #[default]
    Empty,
    FunctionInvocation(FunctionInvocation),
    RevertedReason {
        revert_reason: String,
    },
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct InvokeTxnTrace {
    #[serde(default)]
    pub execute_invocation: ExecuteInvocation,
    #[serde(default)]
    pub fee_transfer_invocation: Option<FunctionInvocation>,
    #[serde(default)]
    pub validate_invocation: Option<FunctionInvocation>,
    pub state_diff: Option<StateDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_resources: Option<ExecutionResources>,
}

impl InvokeTxnTrace {
    pub fn with_v06_format(&mut self) {
        self.execution_resources = None
    }
}

impl From<pathfinder_executor::types::InvokeTransactionTrace> for InvokeTxnTrace {
    fn from(trace: pathfinder_executor::types::InvokeTransactionTrace) -> Self {
        Self {
            validate_invocation: trace.validate_invocation.map(Into::into),
            execute_invocation: match trace.execute_invocation {
                pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(Some(
                    function_invocation,
                )) => ExecuteInvocation::FunctionInvocation(function_invocation.into()),
                pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(None) => {
                    ExecuteInvocation::Empty
                }
                pathfinder_executor::types::ExecuteInvocation::RevertedReason(revert_reason) => {
                    ExecuteInvocation::RevertedReason { revert_reason }
                }
            },
            fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            state_diff: Some(trace.state_diff.into()),
            execution_resources: Some(trace.execution_resources.into()),
        }
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct L1HandlerTxnTrace {
    pub function_invocation: FunctionInvocation,
    pub state_diff: Option<StateDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_resources: Option<ExecutionResources>,
}

impl L1HandlerTxnTrace {
    pub fn with_v06_format(&mut self) {
        self.execution_resources = None
    }
}

impl TryFrom<pathfinder_executor::types::L1HandlerTransactionTrace> for L1HandlerTxnTrace {
    type Error = pathfinder_executor::TransactionExecutionError;

    fn try_from(
        trace: pathfinder_executor::types::L1HandlerTransactionTrace,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            function_invocation: trace
                .function_invocation
                .ok_or_else(|| {
                    Self::Error::Custom(anyhow::anyhow!("Missing function_invocation in trace"))
                })?
                .into(),
            state_diff: Some(trace.state_diff.into()),
            execution_resources: Some(trace.execution_resources.into()),
        })
    }
}

#[serde_with::skip_serializing_none]
#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct SimulatedTransaction {
    #[serde(default)]
    pub fee_estimation: FeeEstimate,
    #[serde(default)]
    pub transaction_trace: TransactionTrace,
}

impl TryFrom<TransactionSimulation> for SimulatedTransaction {
    type Error = pathfinder_executor::TransactionExecutionError;

    fn try_from(tx: TransactionSimulation) -> Result<Self, Self::Error> {
        Ok(Self {
            fee_estimation: tx.fee_estimation.into(),
            transaction_trace: tx.trace.try_into()?,
        })
    }
}

impl SimulatedTransaction {
    pub fn with_v06_format(&mut self) {
        self.fee_estimation.with_v06_format();
        self.transaction_trace.with_v06_format();
    }
}

impl From<gateway_trace::FunctionInvocation> for FunctionInvocation {
    fn from(value: gateway_trace::FunctionInvocation) -> Self {
        Self {
            call_type: value.call_type.map(Into::into).unwrap_or(CallType::Call),
            function_call: FunctionCall {
                calldata: value.calldata.into_iter().map(CallParam).collect(),
                contract_address: value.contract_address,
                entry_point_selector: EntryPoint(value.selector.unwrap_or_default()),
            },
            caller_address: value.caller_address,
            calls: value.internal_calls.into_iter().map(Into::into).collect(),
            class_hash: value.class_hash,
            entry_point_type: value
                .entry_point_type
                .map(Into::into)
                .unwrap_or(EntryPointType::External),
            events: value.events.into_iter().map(Into::into).collect(),
            messages: value
                .messages
                .into_iter()
                .map(|message| OrderedMsgToL1 {
                    order: message.order,
                    payload: message.payload,
                    to_address: message.to_address,
                    from_address: value.contract_address.0,
                })
                .collect(),
            result: value.result,
            execution_resources: {
                let builtins = &value.execution_resources.builtin_instance_counter;
                ComputationResources {
                    steps: value.execution_resources.n_steps as usize,
                    memory_holes: value.execution_resources.n_memory_holes as usize,
                    range_check_builtin_applications: builtins.range_check_builtin as usize,
                    pedersen_builtin_applications: builtins.pedersen_builtin as usize,
                    poseidon_builtin_applications: builtins.poseidon_builtin as usize,
                    ec_op_builtin_applications: builtins.ec_op_builtin as usize,
                    ecdsa_builtin_applications: builtins.ecdsa_builtin as usize,
                    bitwise_builtin_applications: builtins.bitwise_builtin as usize,
                    keccak_builtin_applications: builtins.keccak_builtin as usize,
                    segment_arena_builtin: builtins.segment_arena_builtin as usize,
                }
            },
        }
    }
}

impl From<gateway_trace::CallType> for CallType {
    fn from(value: gateway_trace::CallType) -> Self {
        match value {
            gateway_trace::CallType::Call => Self::Call,
            gateway_trace::CallType::Delegate => Self::Delegate,
        }
    }
}

impl From<gateway_trace::EntryPointType> for EntryPointType {
    fn from(value: gateway_trace::EntryPointType) -> Self {
        match value {
            gateway_trace::EntryPointType::Constructor => Self::Constructor,
            gateway_trace::EntryPointType::External => Self::External,
            gateway_trace::EntryPointType::L1Handler => Self::L1Handler,
        }
    }
}

impl From<gateway_trace::Event> for OrderedEvent {
    fn from(value: gateway_trace::Event) -> Self {
        Self {
            order: value.order,
            data: value.data,
            keys: value.keys,
        }
    }
}
