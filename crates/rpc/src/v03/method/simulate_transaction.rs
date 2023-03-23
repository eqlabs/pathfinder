use crate::{
    cairo::ext_py::{CallFailure, GasPriceSource},
    context::RpcContext,
    error::RpcError,
    v02::{types::{reply::TransactionSimulation, request::BroadcastedTransaction}, method::estimate_fee::base_block_and_pending_for_call},
};
use anyhow::anyhow;
use pathfinder_common::BlockId;
use serde::{Deserialize, Serialize};
use stark_hash::Felt;

pub async fn simulate_transaction(
    context: RpcContext,
    input: SimulateTrasactionInput,
) -> Result<SimulateTransactionResult, SimulateTrasactionError> {
    dbg!(&input); // TODO(SM): remove debug output

    let handle = context
        .call_handle
        .as_ref()
        .ok_or_else(|| SimulateTrasactionError::IllegalState)?;

    let gas_price = if matches!(input.block_id, BlockId::Pending | BlockId::Latest) {
        let gas_price = match context.eth_gas_price.as_ref() {
            Some(cached) => cached.get().await,
            None => None,
        };

        let gas_price =
            gas_price.ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))?;

        GasPriceSource::Current(gas_price)
    } else {
        GasPriceSource::PastBlock
    };

    let (at_block, pending_timestamp, pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;
    
    let skip_execute = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipExecute);
    let skip_validate = input
        .simulation_flags
        .0
        .iter()
        .any(|flag| flag == &dto::SimulationFlag::SkipValidate);
    let txs = handle
        .simulate_transaction(
            at_block,
            gas_price,
            pending_update,
            pending_timestamp,
            &input.transactions,
            skip_execute,
            skip_validate,
        )
        .await
        .map_err(|e| SimulateTrasactionError::CallFailed(e))?;

    dbg!(&txs); // TODO(SM): remove debug output

    let txs = txs.into_iter().map(map_trace).collect();
    Ok(SimulateTransactionResult(txs))
}

fn map_trace(_trace: TransactionSimulation) -> dto::SimulatedTransaction {
    todo!() // TODO!(SM)
}

#[derive(Deserialize, Debug)]
pub struct SimulateTrasactionInput {
    block_id: BlockId,
    transactions: Vec<BroadcastedTransaction>,
    simulation_flags: dto::SimulationFlags,
}

#[derive(Debug, Serialize)]
pub struct SimulateTransactionResult(pub Vec<dto::SimulatedTransaction>);

#[derive(Debug)]
pub enum SimulateTrasactionError {
    Custom(anyhow::Error),
    IllegalState,
    CallFailed(CallFailure),
}

impl From<SimulateTrasactionError> for RpcError {
    fn from(value: SimulateTrasactionError) -> Self {
        match value {
            SimulateTrasactionError::IllegalState | SimulateTrasactionError::CallFailed(_) => {
                RpcError::Internal(anyhow!("Internal error"))
            }
            SimulateTrasactionError::Custom(e) => RpcError::Internal(e)
        }
    }
}

impl From<anyhow::Error> for SimulateTrasactionError {
    fn from(err: anyhow::Error) -> Self {
        Self::Custom(err)
    }
}

pub mod dto {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct SimulationFlags(pub Vec<SimulationFlag>);

    #[derive(Debug, Deserialize, Serialize, Eq, PartialEq)]
    pub enum SimulationFlag {
        #[serde(rename = "SKIP_EXECUTE")]
        SkipExecute,
        #[serde(rename = "SKIP_VALIDATE")]
        SkipValidate,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct Signature(pub Vec<Felt>);

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
    // TODO(SM): consider adding validation by regex (per spec)
    // #[serde(try_from = "String")]
    pub struct NumAsHex(String);
}

// TODO!(SM): tests

/*

{
    "block_id": "latest",
    "transactions": [
        {
        "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
        "max_fee": "0x0",
        "signature": [
            "0x296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88",
            "0x4e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"
        ],
        "class_hash": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
        "nonce": "0x0",
        "version": "0x100000000000000000000000000000001",
        "constructor_calldata": [
            "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
        ],
        "type": "DEPLOY_ACCOUNT"
        }
    ],
    "simulation_flags": []
}

Manual test against call.py:

# cd py
# source .venv/bin/activate
# cd src/pathfinder_worker
# sqlite3 empty.db
> pragma user_version = 30; 
> ^D
# python3 call.py empty.db

{"verb":"SIMULATE_TX","at_block":"latest","chain":"TESTNET","pending_updates":{},"pending_deployed":[],"pending_nonces":{},"pending_timestamp":42,"gas_price":"0x1","transactions":[{"contract_address_salt":"0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971","max_fee":"0x0","signature":["0x296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88","0x4e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"],"class_hash":"0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513","nonce":"0x0","version":"0x100000000000000000000000000000001","constructor_calldata":["0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"],"type":"DEPLOY_ACCOUNT"}]}

 */