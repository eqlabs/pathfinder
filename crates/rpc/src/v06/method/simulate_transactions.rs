use anyhow::Context;
use pathfinder_common::{BlockId, CallParam, EntryPoint};
use pathfinder_crypto::Felt;
use pathfinder_executor::types::TransactionSimulation;
use pathfinder_executor::{L1BlobDataAvailability, TransactionExecutionError};
use serde::{Deserialize, Serialize};

use self::dto::SimulatedTransaction;
use crate::context::RpcContext;
use crate::executor::ExecutionStateError;
use crate::v02::types::request::BroadcastedTransaction;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct SimulateTransactionInput {
    pub block_id: BlockId,
    pub transactions: Vec<BroadcastedTransaction>,
    pub simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct SimulateTransactionOutput(pub Vec<dto::SimulatedTransaction>);

#[derive(Debug)]
pub enum SimulateTransactionError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    TransactionExecutionError {
        transaction_index: usize,
        error: String,
    },
}

impl From<anyhow::Error> for SimulateTransactionError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<SimulateTransactionError> for crate::error::ApplicationError {
    fn from(e: SimulateTransactionError) -> Self {
        match e {
            SimulateTransactionError::Internal(internal) => Self::Internal(internal),
            SimulateTransactionError::Custom(internal) => Self::Custom(internal),
            SimulateTransactionError::BlockNotFound => Self::BlockNotFound,
            SimulateTransactionError::TransactionExecutionError {
                transaction_index,
                error,
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
            },
        }
    }
}

impl From<TransactionExecutionError> for SimulateTransactionError {
    fn from(value: TransactionExecutionError) -> Self {
        use TransactionExecutionError::*;
        match value {
            ExecutionError {
                transaction_index,
                error,
            } => Self::TransactionExecutionError {
                transaction_index,
                error,
            },
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<ExecutionStateError> for SimulateTransactionError {
    fn from(error: ExecutionStateError) -> Self {
        match error {
            ExecutionStateError::BlockNotFound => Self::BlockNotFound,
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn simulate_transactions(
    context: RpcContext,
    input: SimulateTransactionInput,
) -> Result<SimulateTransactionOutput, SimulateTransactionError> {
    simulate_transactions_impl(context, input, L1BlobDataAvailability::Disabled)
        .await
        .map(|mut x| {
            x.0.iter_mut().for_each(|y| y.with_v06_format());
            x
        })
}

pub async fn simulate_transactions_impl(
    context: RpcContext,
    input: SimulateTransactionInput,
    l1_blob_data_availability: L1BlobDataAvailability,
) -> Result<SimulateTransactionOutput, SimulateTransactionError> {
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let skip_validate = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &dto::SimulationFlag::SkipValidate);

        let skip_fee_charge = input
            .simulation_flags
            .0
            .iter()
            .any(|flag| flag == &dto::SimulationFlag::SkipFeeCharge);

        let mut db = context
            .execution_storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let (header, pending) = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                (pending.header(), Some(pending.state_update.clone()))
            }
            other => {
                let block_id = other.try_into().expect("Only pending should fail");

                let header = db
                    .block_header(block_id)
                    .context("Fetching block header")?
                    .ok_or(SimulateTransactionError::BlockNotFound)?;

                (header, None)
            }
        };

        let state = pathfinder_executor::ExecutionState::simulation(
            &db,
            context.chain_id,
            header,
            pending,
            l1_blob_data_availability,
            context.config.custom_versioned_constants,
        );

        let transactions = input
            .transactions
            .into_iter()
            .map(|tx| crate::executor::map_broadcasted_transaction(&tx, context.chain_id))
            .collect::<Result<Vec<_>, _>>()?;

        let txs =
            pathfinder_executor::simulate(state, transactions, skip_validate, skip_fee_charge)?;
        let txs = txs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<SimulatedTransaction>, _>>()?;
        let txs = txs.into_iter().collect();
        Ok(SimulateTransactionOutput(txs))
    })
    .await
    .context("Simulating transaction")?
}

pub mod dto {
    use serde_with::serde_as;
    use starknet_gateway_types::trace as gateway_trace;

    use super::*;
    use crate::felt::RpcFelt;
    use crate::v03::method::get_state_update::types::StateDiff;
    use crate::v06::method::call::FunctionCall;
    use crate::v06::types::PriceUnit;

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
                gas_consumed: value.gas_consumed,
                gas_price: value.gas_price,
                data_gas_consumed: Some(value.data_gas_consumed),
                data_gas_price: Some(value.data_gas_price),
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

    #[derive(Clone, Debug, Serialize, Eq, PartialEq)]
    #[serde(tag = "type")]
    pub enum TransactionTrace {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTxnTrace),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccountTxnTrace),
        #[serde(rename = "INVOKE")]
        Invoke(InvokeTxnTrace),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTxnTrace),
    }

    impl TransactionTrace {
        pub fn with_v06_format(&mut self) {
            match self {
                TransactionTrace::Declare(tx) => tx.with_v06_format(),
                TransactionTrace::DeployAccount(tx) => tx.with_v06_format(),
                TransactionTrace::Invoke(tx) => tx.with_v06_format(),
                TransactionTrace::L1Handler(tx) => tx.with_v06_format(),
            }
        }
    }

    impl TryFrom<pathfinder_executor::types::TransactionTrace> for TransactionTrace {
        type Error = pathfinder_executor::TransactionExecutionError;

        fn try_from(
            trace: pathfinder_executor::types::TransactionTrace,
        ) -> Result<Self, Self::Error> {
            use pathfinder_executor::types::TransactionTrace::*;
            Ok(match trace {
                Declare(t) => Self::Declare(t.into()),
                DeployAccount(t) => Self::DeployAccount(t.try_into()?),
                Invoke(t) => Self::Invoke(t.into()),
                L1Handler(t) => Self::L1Handler(t.try_into()?),
            })
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
                        Self::Error::Custom(anyhow::anyhow!(
                            "Missing constructor_invocation in trace"
                        ))
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
                    pathfinder_executor::types::ExecuteInvocation::RevertedReason(
                        revert_reason,
                    ) => ExecuteInvocation::RevertedReason { revert_reason },
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
            Ok(dto::SimulatedTransaction {
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
}

#[cfg(test)]
pub(crate) mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt,
        BlockHeader,
        ClassHash,
        ContractAddress,
        StarknetVersion,
        StorageAddress,
        StorageValue,
        TransactionVersion,
    };
    use pathfinder_storage::Storage;
    use starknet_gateway_test_fixtures::class_definitions::{
        DUMMY_ACCOUNT_CLASS_HASH,
        ERC20_CONTRACT_DEFINITION_CLASS_HASH,
    };

    use super::*;
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction,
        BroadcastedDeclareTransactionV1,
    };
    use crate::v02::types::ContractClass;
    use crate::v03::method::get_state_update::types::{DeployedContract, Nonce, StateDiff};
    use crate::v06::method::call::FunctionCall;
    use crate::v06::types::PriceUnit;

    pub(crate) async fn setup_storage_with_starknet_version(
        version: StarknetVersion,
    ) -> (
        Storage,
        BlockHeader,
        ContractAddress,
        ContractAddress,
        StorageValue,
    ) {
        let test_storage_key = StorageAddress::from_name(b"my_storage_var");
        let test_storage_value = storage_value!("0x09");

        // set test storage variable
        let (storage, last_block_header, account_contract_address, universal_deployer_address) =
            crate::test_setup::test_storage(version, |state_update| {
                state_update.with_storage_update(
                    fixtures::DEPLOYED_CONTRACT_ADDRESS,
                    test_storage_key,
                    test_storage_value,
                )
            })
            .await;

        (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        )
    }

    #[tokio::test]
    async fn test_simulate_transaction_with_skip_fee_charge() {
        let (context, _, _, _) = crate::test_setup::test_context().await;

        let input_json = serde_json::json!({
            "block_id": {"block_number": 1},
            "transactions": [
                {
                    "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "max_fee": "0x0",
                    "signature": [],
                    "class_hash": DUMMY_ACCOUNT_CLASS_HASH,
                    "nonce": "0x0",
                    "version": TransactionVersion::ONE_WITH_QUERY_VERSION,
                    "constructor_calldata": [],
                    "type": "DEPLOY_ACCOUNT"
                }
            ],
            "simulation_flags": ["SKIP_FEE_CHARGE"]
        });
        let input = SimulateTransactionInput::deserialize(&input_json).unwrap();

        let expected: Vec<dto::SimulatedTransaction> = {
            use dto::*;
            vec![
            SimulatedTransaction {
                fee_estimation:
                    FeeEstimate {
                        gas_consumed: 2222.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: None,
                        data_gas_price: None,
                        overall_fee: 2222.into(),
                        unit: PriceUnit::Wei,
                    }
                ,
                transaction_trace:
                    TransactionTrace::DeployAccount(
                        DeployAccountTxnTrace {
                            constructor_invocation: FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::Constructor,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                    execution_resources: ComputationResources::default(),
                                },
                            validate_invocation: Some(
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: felt!("0x0"),
                                    calls: vec![],
                                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                                    entry_point_type: EntryPointType::External,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        calldata: vec![
                                            CallParam(DUMMY_ACCOUNT_CLASS_HASH.0),
                                            call_param!("0x046C0D4ABF0192A788ACA261E58D7031576F7D8EA5229F452B0F23E691DD5971"),
                                        ],
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        entry_point_selector: entry_point!("0x036FCBF06CD96843058359E1A75928BEACFAC10727DAB22A3972F0AF8AA92895"),
                                    },
                                    messages: vec![],
                                    result: vec![],
                                    execution_resources: ComputationResources {
                                        steps: 13,
                                        ..Default::default()
                                    },
                                },
                            ),
                            fee_transfer_invocation: None,
                            state_diff: Some(StateDiff {
                                storage_diffs: vec![],
                                deprecated_declared_classes: vec![],
                                declared_classes: vec![],
                                deployed_contracts: vec![
                                    DeployedContract {
                                        address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        class_hash: DUMMY_ACCOUNT_CLASS_HASH
                                    }
                                ],
                                replaced_classes: vec![],
                                nonces: vec![
                                    Nonce {
                                        contract_address: contract_address!("0x00798C1BFDAF2077F4900E37C8815AFFA8D217D46DB8A84C3FBA1838C8BD4A65"),
                                        nonce: contract_nonce!("0x1")
                                    }
                                ]
                            }),
                            execution_resources: None,
                        },
                    ),
            }]
        };

        let result = simulate_transactions(context, input).await.expect("result");
        pretty_assertions_sorted::assert_eq!(result.0, expected);
    }

    #[tokio::test]
    async fn declare_cairo_v0_class() {
        pub const CAIRO0_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/cairo0_test.json");

        pub const CAIRO0_HASH: ClassHash =
            class_hash!("02c52e7084728572ea940b4df708a2684677c19fa6296de2ea7ba5327e3a84ef");

        let contract_class = ContractClass::from_definition_bytes(CAIRO0_DEFINITION)
            .unwrap()
            .as_cairo()
            .unwrap();

        assert_eq!(contract_class.class_hash().unwrap().hash(), CAIRO0_HASH);

        let (storage, last_block_header, account_contract_address, _, _) =
            setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let declare = BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                max_fee: fee!("0x10000"),
                signature: vec![],
                nonce: transaction_nonce!("0x0"),
                contract_class,
                sender_address: account_contract_address,
            },
        ));

        let input = SimulateTransactionInput {
            block_id: last_block_header.number.into(),
            transactions: vec![declare],
            simulation_flags: dto::SimulationFlags(vec![]),
        };

        let result = simulate_transactions(context, input).await.unwrap();

        const DECLARE_GAS_CONSUMED: u64 = 2225;
        use super::dto::*;
        use crate::v03::method::get_state_update::types::{StorageDiff, StorageEntry};

        pretty_assertions_sorted::assert_eq!(
            result,
            SimulateTransactionOutput(vec![SimulatedTransaction {
                fee_estimation: FeeEstimate {
                    gas_consumed: DECLARE_GAS_CONSUMED.into(),
                    gas_price: 1.into(),
                    data_gas_consumed: None,
                    data_gas_price: None,
                    overall_fee: DECLARE_GAS_CONSUMED.into(),
                    unit: PriceUnit::Wei,
                },
                transaction_trace: TransactionTrace::Declare(DeclareTxnTrace {
                    fee_transfer_invocation: Some(
                        FunctionInvocation {
                            call_type: CallType::Call,
                            caller_address: *account_contract_address.get(),
                            calls: vec![],
                            class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                            entry_point_type: EntryPointType::External,
                            events: vec![OrderedEvent {
                                order: 0,
                                data: vec![
                                    *account_contract_address.get(),
                                    last_block_header.sequencer_address.0,
                                    Felt::from_u64(DECLARE_GAS_CONSUMED),
                                    felt!("0x0"),
                                ],
                                keys: vec![felt!(
                                    "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                                )],
                            }],
                            function_call: FunctionCall {
                                calldata: vec![
                                    CallParam(last_block_header.sequencer_address.0),
                                    CallParam(Felt::from_u64(DECLARE_GAS_CONSUMED)),
                                    call_param!("0x0"),
                                ],
                                contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                                entry_point_selector: EntryPoint::hashed(b"transfer"),
                            },
                            messages: vec![],
                            result: vec![felt!("0x1")],
                            execution_resources: ComputationResources {
                                steps: 1354,
                                memory_holes: 59,
                                range_check_builtin_applications: 31,
                                pedersen_builtin_applications: 4,
                                ..Default::default()
                            },
                        }
                    ),
                    validate_invocation: Some(
                        FunctionInvocation {
                            call_type: CallType::Call,
                            caller_address: felt!("0x0"),
                            calls: vec![],
                            class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                            entry_point_type: EntryPointType::External,
                            events: vec![],
                            function_call: FunctionCall {
                                contract_address: account_contract_address,
                                entry_point_selector: EntryPoint::hashed(b"__validate_declare__"),
                                calldata: vec![CallParam(CAIRO0_HASH.0)],
                            },
                            messages: vec![],
                            result: vec![],
                            execution_resources: ComputationResources {
                                steps: 12,
                                ..Default::default()
                            },
                        }
                    ),
                    state_diff: Some(StateDiff {
                        storage_diffs: vec![StorageDiff {
                            address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                            storage_entries: vec![
                                StorageEntry {
                                    key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                                    value: storage_value!("0x000000000000000000000000000000000000fffffffffffffffffffffffff74f")
                                },
                                StorageEntry {
                                    key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                                    value: StorageValue(DECLARE_GAS_CONSUMED.into()),
                                },
                            ],
                        }],
                        deprecated_declared_classes: vec![
                            CAIRO0_HASH
                        ],
                        declared_classes: vec![],
                        deployed_contracts: vec![],
                        replaced_classes: vec![],
                        nonces: vec![Nonce {
                            contract_address: account_contract_address,
                            nonce: contract_nonce!("0x1"),
                        }],
                    }),
                    execution_resources: None,
                }),
            }])
        );
    }

    pub(crate) mod fixtures {
        use pathfinder_common::{CasmHash, ContractAddress, Fee};

        use super::*;

        pub const SIERRA_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/storage_access.json");
        pub const SIERRA_HASH: ClassHash =
            class_hash!("0544b92d358447cb9e50b65092b7169f931d29e05c1404a2cd08c6fd7e32ba90");
        pub const CASM_HASH: CasmHash =
            casm_hash!("0x069032ff71f77284e1a0864a573007108ca5cc08089416af50f03260f5d6d4d8");
        pub const CASM_DEFINITION: &[u8] =
            include_bytes!("../../../fixtures/contracts/storage_access.casm");
        const MAX_FEE: Fee = Fee(Felt::from_u64(10_000_000));
        pub const DEPLOYED_CONTRACT_ADDRESS: ContractAddress =
            contract_address!("0x012592426632af714f43ccb05536b6044fc3e897fa55288f658731f93590e7e7");
        pub const UNIVERSAL_DEPLOYER_CLASS_HASH: ClassHash =
            class_hash!("0x06f38fb91ddbf325a0625533576bb6f6eafd9341868a9ec3faa4b01ce6c4f4dc");

        // The input transactions are the same as in v04.
        pub mod input {
            use pathfinder_common::{
                CallParam,
                EntryPoint,
                ResourceAmount,
                ResourcePricePerUnit,
                Tip,
            };

            use super::*;
            use crate::v02::types::request::{
                BroadcastedDeclareTransactionV2,
                BroadcastedInvokeTransaction,
                BroadcastedInvokeTransactionV1,
                BroadcastedInvokeTransactionV3,
                BroadcastedTransaction,
            };
            use crate::v02::types::{ResourceBound, ResourceBounds};

            pub fn declare(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                let contract_class = ContractClass::from_definition_bytes(SIERRA_DEFINITION)
                    .unwrap()
                    .as_sierra()
                    .unwrap();

                assert_eq!(contract_class.class_hash().unwrap().hash(), SIERRA_HASH);

                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
                    BroadcastedDeclareTransactionV2 {
                        version: TransactionVersion::TWO,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        nonce: transaction_nonce!("0x0"),
                        contract_class,
                        sender_address: account_contract_address,
                        compiled_class_hash: CASM_HASH,
                    },
                ))
            }

            pub fn universal_deployer(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        nonce: transaction_nonce!("0x1"),
                        version: TransactionVersion::ONE,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        sender_address: account_contract_address,
                        calldata: vec![
                            CallParam(*universal_deployer_address.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("4"),
                            // classHash
                            CallParam(SIERRA_HASH.0),
                            // salt
                            call_param!("0x0"),
                            // unique
                            call_param!("0x0"),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                ))
            }

            pub fn invoke(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                    BroadcastedInvokeTransactionV1 {
                        nonce: transaction_nonce!("0x2"),
                        version: TransactionVersion::ONE,
                        max_fee: MAX_FEE,
                        signature: vec![],
                        sender_address: account_contract_address,
                        calldata: vec![
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }

            pub fn invoke_v3(account_contract_address: ContractAddress) -> BroadcastedTransaction {
                BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V3(
                    BroadcastedInvokeTransactionV3 {
                        version: TransactionVersion::THREE,
                        signature: vec![],
                        nonce: transaction_nonce!("0x3"),
                        resource_bounds: ResourceBounds {
                            l1_gas: ResourceBound {
                                max_amount: ResourceAmount(10000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            },
                            l2_gas: ResourceBound {
                                max_amount: ResourceAmount(10000),
                                max_price_per_unit: ResourcePricePerUnit(100000000),
                            },
                        },
                        tip: Tip(0),
                        paymaster_data: vec![],
                        account_deployment_data: vec![],
                        nonce_data_availability_mode: crate::v02::types::DataAvailabilityMode::L1,
                        fee_data_availability_mode: crate::v02::types::DataAvailabilityMode::L1,
                        sender_address: account_contract_address,
                        calldata: vec![
                            CallParam(*DEPLOYED_CONTRACT_ADDRESS.get()),
                            // Entry point selector for the called contract, i.e.
                            // AccountCallArray::selector
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // Length of the call data for the called contract, i.e.
                            // AccountCallArray::data_len
                            call_param!("0"),
                        ],
                    },
                ))
            }
        }

        pub mod expected_output_0_13_1_1 {
            use pathfinder_common::{BlockHeader, ContractAddress, SierraHash, StorageValue};

            use super::dto::*;
            use super::*;
            use crate::v03::method::get_state_update::types::{
                DeclaredSierraClass,
                StorageDiff,
                StorageEntry,
            };

            const DECLARE_GAS_CONSUMED: u64 = 3632;

            pub fn declare(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: DECLARE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: None,
                        data_gas_price: None,
                        overall_fee: DECLARE_GAS_CONSUMED.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Declare(DeclareTxnTrace {
                        fee_transfer_invocation: Some(declare_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        validate_invocation: Some(declare_validate(account_contract_address)),
                        state_diff: Some(declare_state_diff(
                            account_contract_address,
                            declare_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: None,
                    }),
                }
            }

            fn declare_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![DeclaredSierraClass {
                        class_hash: SierraHash(SIERRA_HASH.0),
                        compiled_class_hash: CASM_HASH,
                    }],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x1"),
                    }],
                }
            }

            fn declare_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000fffffffffffffffffffffffff1d0")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue(DECLARE_GAS_CONSUMED.into()),
                        },
                    ],
                }]
            }

            fn declare_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(DECLARE_GAS_CONSUMED),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(DECLARE_GAS_CONSUMED)),
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: ComputationResources {
                        steps: 1354,
                        memory_holes: 59,
                        range_check_builtin_applications: 31,
                        pedersen_builtin_applications: 4,
                        ..Default::default()
                    },
                }
            }

            fn declare_validate(account_contract_address: ContractAddress) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__validate_declare__"),
                        calldata: vec![CallParam(SIERRA_HASH.0)],
                    },
                    messages: vec![],
                    result: vec![],
                    execution_resources: ComputationResources {
                        steps: 12,
                        ..Default::default()
                    },
                }
            }

            const UNIVERSAL_DEPLOYER_GAS_CONSUMED: u64 = 3009;

            pub fn universal_deployer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                universal_deployer_address: ContractAddress,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: UNIVERSAL_DEPLOYER_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: None,
                        data_gas_price: None,
                        overall_fee: UNIVERSAL_DEPLOYER_GAS_CONSUMED.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(universal_deployer_validate(
                            account_contract_address,
                            universal_deployer_address,
                        )),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(
                            universal_deployer_execute(
                                account_contract_address,
                                universal_deployer_address,
                            ),
                        ),
                        fee_transfer_invocation: Some(universal_deployer_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(universal_deployer_state_diff(
                            account_contract_address,
                            universal_deployer_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: None,
                    }),
                }
            }

            fn universal_deployer_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![],
                    deployed_contracts: vec![DeployedContract {
                        address: DEPLOYED_CONTRACT_ADDRESS,
                        class_hash: SIERRA_HASH,
                    }],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x2"),
                    }],
                }
            }

            fn universal_deployer_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000ffffffffffffffffffffffffe60f")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((DECLARE_GAS_CONSUMED + UNIVERSAL_DEPLOYER_GAS_CONSUMED).into()),
                        },
                    ],
                }]
            }

            fn universal_deployer_validate(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__validate__"),
                        calldata: vec![
                            CallParam(universal_deployer_address.0),
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            // calldata_len
                            call_param!("0x4"),
                            // classHash
                            CallParam(SIERRA_HASH.0),
                            // salt
                            call_param!("0x0"),
                            // unique
                            call_param!("0x0"),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                    messages: vec![],
                    result: vec![],
                    execution_resources: ComputationResources {
                        steps: 21,
                        range_check_builtin_applications: 1,
                        ..Default::default()
                    },
                }
            }

            fn universal_deployer_execute(
                account_contract_address: ContractAddress,
                universal_deployer_address: ContractAddress,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![
                        FunctionInvocation {
                            call_type: CallType::Call,
                            caller_address: *account_contract_address.get(),
                            calls: vec![
                                FunctionInvocation {
                                    call_type: CallType::Call,
                                    caller_address: *universal_deployer_address.get(),
                                    calls: vec![],
                                    class_hash: Some(SIERRA_HASH.0),
                                    entry_point_type: EntryPointType::Constructor,
                                    events: vec![],
                                    function_call: FunctionCall {
                                        contract_address: DEPLOYED_CONTRACT_ADDRESS,
                                        entry_point_selector: EntryPoint::hashed(b"constructor"),
                                        calldata: vec![],
                                    },
                                    messages: vec![],
                                    result: vec![],
                                    execution_resources: ComputationResources::default(),
                                },
                            ],
                            class_hash: Some(UNIVERSAL_DEPLOYER_CLASS_HASH.0),
                            entry_point_type: EntryPointType::External,
                            events: vec![
                                OrderedEvent {
                                    order: 0,
                                    data: vec![
                                        *DEPLOYED_CONTRACT_ADDRESS.get(),
                                        *account_contract_address.get(),
                                        felt!("0x0"),
                                        SIERRA_HASH.0,
                                        felt!("0x0"),
                                        felt!("0x0"),
                                    ],
                                    keys: vec![
                                        felt!("0x026B160F10156DEA0639BEC90696772C640B9706A47F5B8C52EA1ABE5858B34D"),
                                    ]
                                },
                            ],
                            function_call: FunctionCall {
                                contract_address: universal_deployer_address,
                                entry_point_selector: EntryPoint::hashed(b"deployContract"),
                                calldata: vec![
                                    // classHash
                                    CallParam(SIERRA_HASH.0),
                                    // salt
                                    call_param!("0x0"),
                                    // unique
                                    call_param!("0x0"),
                                    //  calldata_len
                                    call_param!("0x0"),
                                ],
                            },
                            messages: vec![],
                            result: vec![
                                *DEPLOYED_CONTRACT_ADDRESS.get(),
                            ],
                            execution_resources: ComputationResources {
                                steps: 1262,
                                memory_holes: 2,
                                range_check_builtin_applications: 23,
                                pedersen_builtin_applications: 7,
                                ..Default::default()
                            },
                        }
                    ],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__execute__"),
                        calldata: vec![
                            CallParam(universal_deployer_address.0),
                            CallParam(EntryPoint::hashed(b"deployContract").0),
                            call_param!("0x4"),
                            // classHash
                            CallParam(SIERRA_HASH.0),
                            // salt
                            call_param!("0x0"),
                            // unique
                            call_param!("0x0"),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                    messages: vec![],
                    result: vec![
                        *DEPLOYED_CONTRACT_ADDRESS.get(),
                    ],
                    execution_resources: ComputationResources {
                        steps: 2061,
                        memory_holes: 2,
                        range_check_builtin_applications: 44,
                        pedersen_builtin_applications: 7,
                        ..Default::default()
                    },
                }
            }

            fn universal_deployer_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(UNIVERSAL_DEPLOYER_GAS_CONSUMED),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(UNIVERSAL_DEPLOYER_GAS_CONSUMED)),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: ComputationResources {
                        steps: 1354,
                        memory_holes: 59,
                        range_check_builtin_applications: 31,
                        pedersen_builtin_applications: 4,
                        ..Default::default()
                    },
                }
            }

            const INVOKE_GAS_CONSUMED: u64 = 1664;

            pub fn invoke(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
                test_storage_value: StorageValue,
            ) -> SimulatedTransaction {
                SimulatedTransaction {
                    fee_estimation: FeeEstimate {
                        gas_consumed: INVOKE_GAS_CONSUMED.into(),
                        gas_price: 1.into(),
                        data_gas_consumed: None,
                        data_gas_price: None,
                        overall_fee: INVOKE_GAS_CONSUMED.into(),
                        unit: PriceUnit::Wei,
                    },
                    transaction_trace: TransactionTrace::Invoke(InvokeTxnTrace {
                        validate_invocation: Some(invoke_validate(account_contract_address)),
                        execute_invocation: ExecuteInvocation::FunctionInvocation(invoke_execute(
                            account_contract_address,
                            test_storage_value,
                        )),
                        fee_transfer_invocation: Some(invoke_fee_transfer(
                            account_contract_address,
                            last_block_header,
                        )),
                        state_diff: Some(invoke_state_diff(
                            account_contract_address,
                            invoke_fee_transfer_storage_diffs(),
                        )),
                        execution_resources: None,
                    }),
                }
            }

            fn invoke_state_diff(
                account_contract_address: ContractAddress,
                storage_diffs: Vec<StorageDiff>,
            ) -> StateDiff {
                StateDiff {
                    storage_diffs,
                    deprecated_declared_classes: vec![],
                    declared_classes: vec![],
                    deployed_contracts: vec![],
                    replaced_classes: vec![],
                    nonces: vec![Nonce {
                        contract_address: account_contract_address,
                        nonce: contract_nonce!("0x3"),
                    }],
                }
            }

            fn invoke_fee_transfer_storage_diffs() -> Vec<StorageDiff> {
                vec![StorageDiff {
                    address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                    storage_entries: vec![
                        StorageEntry {
                            key: storage_address!("0x032a4edd4e4cffa71ee6d0971c54ac9e62009526cd78af7404aa968c3dc3408e"),
                            value: storage_value!("0x000000000000000000000000000000000000ffffffffffffffffffffffffdf8f")
                        },
                        StorageEntry {
                            key: storage_address!("0x05496768776e3db30053404f18067d81a6e06f5a2b0de326e21298fd9d569a9a"),
                            value: StorageValue((DECLARE_GAS_CONSUMED + UNIVERSAL_DEPLOYER_GAS_CONSUMED + INVOKE_GAS_CONSUMED).into()),
                        },
                    ],
                }]
            }

            fn invoke_validate(account_contract_address: ContractAddress) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__validate__"),
                        calldata: vec![
                            CallParam(DEPLOYED_CONTRACT_ADDRESS.0),
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                    messages: vec![],
                    result: vec![],
                    execution_resources: ComputationResources {
                        steps: 21,
                        range_check_builtin_applications: 1,
                        ..Default::default()
                    },
                }
            }

            fn invoke_execute(
                account_contract_address: ContractAddress,
                test_storage_value: StorageValue,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: felt!("0x0"),
                    calls: vec![FunctionInvocation {
                        call_type: CallType::Call,
                        caller_address: *account_contract_address.get(),
                        calls: vec![],
                        class_hash: Some(SIERRA_HASH.0),
                        entry_point_type: EntryPointType::External,
                        events: vec![],
                        function_call: FunctionCall {
                            contract_address: DEPLOYED_CONTRACT_ADDRESS,
                            entry_point_selector: EntryPoint::hashed(b"get_data"),
                            calldata: vec![],
                        },
                        messages: vec![],
                        result: vec![test_storage_value.0],
                        execution_resources: ComputationResources {
                            steps: 165,
                            range_check_builtin_applications: 3,
                            ..Default::default()
                        },
                    }],
                    class_hash: Some(DUMMY_ACCOUNT_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![],
                    function_call: FunctionCall {
                        contract_address: account_contract_address,
                        entry_point_selector: EntryPoint::hashed(b"__execute__"),
                        calldata: vec![
                            CallParam(DEPLOYED_CONTRACT_ADDRESS.0),
                            CallParam(EntryPoint::hashed(b"get_data").0),
                            // calldata_len
                            call_param!("0x0"),
                        ],
                    },
                    messages: vec![],
                    result: vec![test_storage_value.0],
                    execution_resources: ComputationResources {
                        steps: 964,
                        range_check_builtin_applications: 24,
                        ..Default::default()
                    },
                }
            }

            fn invoke_fee_transfer(
                account_contract_address: ContractAddress,
                last_block_header: &BlockHeader,
            ) -> FunctionInvocation {
                FunctionInvocation {
                    call_type: CallType::Call,
                    caller_address: *account_contract_address.get(),
                    calls: vec![],
                    class_hash: Some(ERC20_CONTRACT_DEFINITION_CLASS_HASH.0),
                    entry_point_type: EntryPointType::External,
                    events: vec![OrderedEvent {
                        order: 0,
                        data: vec![
                            *account_contract_address.get(),
                            last_block_header.sequencer_address.0,
                            Felt::from_u64(INVOKE_GAS_CONSUMED),
                            felt!("0x0"),
                        ],
                        keys: vec![felt!(
                            "0x0099CD8BDE557814842A3121E8DDFD433A539B8C9F14BF31EBF108D12E6196E9"
                        )],
                    }],
                    function_call: FunctionCall {
                        calldata: vec![
                            CallParam(last_block_header.sequencer_address.0),
                            CallParam(Felt::from_u64(INVOKE_GAS_CONSUMED)),
                            call_param!("0x0"),
                        ],
                        contract_address: pathfinder_executor::ETH_FEE_TOKEN_ADDRESS,
                        entry_point_selector: EntryPoint::hashed(b"transfer"),
                    },
                    messages: vec![],
                    result: vec![felt!("0x1")],
                    execution_resources: ComputationResources {
                        steps: 1354,
                        memory_holes: 59,
                        range_check_builtin_applications: 31,
                        pedersen_builtin_applications: 4,
                        ..Default::default()
                    },
                }
            }
        }
    }

    #[test_log::test(tokio::test)]
    async fn declare_deploy_and_invoke_sierra_class_for_starknet_0_13_1_1() {
        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = SimulateTransactionInput {
            transactions: vec![
                fixtures::input::declare(account_contract_address),
                fixtures::input::universal_deployer(
                    account_contract_address,
                    universal_deployer_address,
                ),
                fixtures::input::invoke(account_contract_address),
            ],
            block_id: BlockId::Number(last_block_header.number),
            simulation_flags: dto::SimulationFlags(vec![]),
        };
        let result = simulate_transactions(context, input).await.unwrap();

        pretty_assertions_sorted::assert_eq!(
            result,
            SimulateTransactionOutput(vec![
                fixtures::expected_output_0_13_1_1::declare(
                    account_contract_address,
                    &last_block_header
                ),
                fixtures::expected_output_0_13_1_1::universal_deployer(
                    account_contract_address,
                    &last_block_header,
                    universal_deployer_address,
                ),
                fixtures::expected_output_0_13_1_1::invoke(
                    account_contract_address,
                    &last_block_header,
                    test_storage_value,
                ),
            ])
        );
    }
}
