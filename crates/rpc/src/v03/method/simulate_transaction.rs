use crate::{context::RpcContext, error::RpcError};
use anyhow::anyhow;
use pathfinder_common::BlockId;
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionResult, SimulateTrasactionError> {
    dbg!(input);

    let handle = context
        .call_handle
        .as_ref()
        .ok_or_else(|| SimulateTrasactionError::IllegalState)?;

    // TODO(SM)

    let _ = handle.simulate_transaction()
        .await
        .map_err(|_| SimulateTrasactionError::CallFailed)?;

    Ok(SimulateTransactionResult(vec![]))
}

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    transaction: dto::Transaction,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize)]
pub struct SimulateTransactionResult(pub Vec<dto::SimulatedTransaction>);

#[derive(Debug)]
pub enum SimulateTrasactionError {
    IllegalState,
    CallFailed,
}

impl From<SimulateTrasactionError> for RpcError {
    fn from(value: SimulateTrasactionError) -> Self {
        match value {
            SimulateTrasactionError::IllegalState | SimulateTrasactionError::CallFailed => {
                RpcError::Internal(anyhow!("Internal error"))
            }
        }
    }
}

pub mod dto {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Transaction(pub Vec<BroadcastedTxn>);

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    pub enum BroadcastedTxn {
        BroadcastedDeclareTxn(BroadcastedDeclareTxn),
        BroadcastedDeployAccountTxn(BroadcastedDeployAccountTxn),
        BroadcastedInvokeTxn(BroadcastedInvokeTxn),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct BroadcastedTxnCommonProperties {
        pub max_fee: Felt,
        pub nonce: Felt,
        pub signature: Signature,
        pub version: NumAsHex,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Signature(pub Vec<Felt>);

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    pub enum BroadcastedDeclareTxn {
        BroadcastedDeclareTxnV1(BroadcastedDeclareTxnV1),
        BroadcastedDeclareTxnV2(BroadcastedDeclareTxnV2),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct BroadcastedDeclareTxnV1 {
        #[serde(flatten)]
        pub broadcasted_txn_common_properties: BroadcastedTxnCommonProperties,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub contract_class: Option<DeprecatedContractClass>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sender_address: Option<Address>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct BroadcastedDeclareTxnV2 {
        #[serde(flatten)]
        pub broadcasted_txn_common_properties: BroadcastedTxnCommonProperties,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compiled_class_hash: Option<Felt>,
        pub contract_class: ContractClass,
        pub sender_address: Address,
        #[serde(rename = "type")]
        pub r#type: BroadcastedDeclareTxnV2Type,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ContractClass {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub abi: Option<String>,
        pub contract_class_version: String,
        pub entry_points_by_type: ContractClassEntryPoint,
        pub sierra_program: Vec<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SierraEntryPoint {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub function_idx: Option<i64>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub selector: Option<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ContractClassEntryPoint {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "CONSTRUCTOR")]
        pub constructor: Option<Vec<SierraEntryPoint>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "EXTERNAL")]
        pub external: Option<Vec<SierraEntryPoint>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "L1_HANDLER")]
        pub l1_handler: Option<Vec<SierraEntryPoint>>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeprecatedContractClass {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub abi: Option<ContractAbi>,
        pub entry_points_by_type: DeprecatedContractClassEntryPoint,
        pub program: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeprecatedContractClassEntryPoint {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "CONSTRUCTOR")]
        pub constructor: Option<Vec<DeprecatedCairoEntryPoint>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "EXTERNAL")]
        pub external: Option<Vec<DeprecatedCairoEntryPoint>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "L1_HANDLER")]
        pub l1_handler: Option<Vec<DeprecatedCairoEntryPoint>>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeprecatedCairoEntryPoint {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub offset: Option<NumAsHex>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub selector: Option<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct ContractAbi(pub Vec<ContractAbiEntry>);

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    pub enum ContractAbiEntry {
        EventAbiEntry(EventAbiEntry),
        FunctionAbiEntry(FunctionAbiEntry),
        StructAbiEntry(StructAbiEntry),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FunctionAbiEntry {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub inputs: Option<Vec<TypedParameter>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub outputs: Option<Vec<TypedParameter>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "type")]
        pub r#type: Option<FunctionAbiType>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum FunctionAbiType {
        #[serde(rename = "constructor")]
        Constructor,
        #[serde(rename = "function")]
        Function,
        #[serde(rename = "l1_handler")]
        L1Handler,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct StructAbiEntry {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub members: Option<Vec<StructMember>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<i64>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "type")]
        pub r#type: Option<StructAbiType>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum StructAbiType {
        #[serde(rename = "struct")]
        Struct,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct StructMember {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub offset: Option<i64>,
        #[serde(flatten)]
        pub typed_parameter: TypedParameter,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct EventAbiEntry {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub data: Option<Vec<TypedParameter>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub keys: Option<Vec<TypedParameter>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "type")]
        pub r#type: Option<EventAbiType>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum EventAbiType {
        #[serde(rename = "event")]
        Event,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct TypedParameter {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub name: Option<String>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "type")]
        pub r#type: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum BroadcastedDeclareTxnV2Type {
        #[serde(rename = "DECLARE")]
        Declare,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct BroadcastedDeployAccountTxn {
        #[serde(flatten)]
        pub broadcasted_txn_common_properties: BroadcastedTxnCommonProperties,
        #[serde(flatten)]
        pub deploy_account_txn_properties: DeployAccountTxnProperties,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeployAccountTxnProperties {
        pub class_hash: Felt,
        pub constructor_calldata: Vec<Felt>,
        pub contract_address_salt: Felt,
        #[serde(rename = "type")]
        pub r#type: DeployAccountTxnPropertiesType,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum DeployAccountTxnPropertiesType {
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct BroadcastedInvokeTxn {
        #[serde(flatten)]
        pub broadcasted_invoke_txn_kind: BroadcastedInvokeTxnKind,
        #[serde(flatten)]
        pub broadcasted_txn_common_properties: BroadcastedTxnCommonProperties,
        #[serde(rename = "type")]
        pub r#type: BroadcastedInvokeTxnType,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    pub enum BroadcastedInvokeTxnKind {
        FunctionCall(FunctionCall),
        InvokeTxnV1(InvokeTxnV1),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct InvokeTxnV1 {
        pub calldata: Vec<Felt>,
        pub sender_address: Address,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum BroadcastedInvokeTxnType {
        #[serde(rename = "INVOKE")]
        Invoke,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Address(pub Felt);

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FunctionCall {
        pub calldata: Vec<Felt>,
        pub contract_address: Address,
        pub entry_point_selector: Felt,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum CallType {
        #[serde(rename = "CALL")]
        Call,
        #[serde(rename = "LIBRARY_CALL")]
        LibraryCall,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum EntryPointType {
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FunctionInvocation {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub call_type: Option<CallType>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub caller_address: Option<Felt>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub calls: Option<Vec<FunctionInvocation>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub code_address: Option<Felt>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub events: Option<Vec<Event>>,
        #[serde(flatten)]
        pub function_call: FunctionCall,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub messages: Option<Vec<MsgToL1>>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub result: Option<Vec<Felt>>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct MsgToL1 {
        pub payload: Vec<Felt>,
        pub to_address: Felt,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Event {
        #[serde(flatten)]
        pub event_content: EventContent,
        pub from_address: Address,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct EventContent {
        pub data: Vec<Felt>,
        pub keys: Vec<Felt>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    #[serde(untagged)]
    pub enum TransactionTrace {
        DeclareTxnTrace(DeclareTxnTrace),
        DeployAccountTxnTrace(DeployAccountTxnTrace),
        InvokeTxnTrace(InvokeTxnTrace),
        L1HandlerTxnTrace(L1HandlerTxnTrace),
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeclareTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct DeployAccountTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub constructor_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct InvokeTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub execute_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_transfer_invocation: Option<FunctionInvocation>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub validate_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct L1HandlerTxnTrace {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub function_invocation: Option<FunctionInvocation>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SimulatedTransaction {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fee_estimation: Option<FeeEstimate>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transaction_trace: Option<TransactionTrace>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct FeeEstimate {
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub gas_consumed: Option<NumAsHex>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub gas_price: Option<NumAsHex>,
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub overall_fee: Option<NumAsHex>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    // #[serde(try_from = "String")] // TODO: consider adding validation by regex
    pub struct NumAsHex(String);
}
