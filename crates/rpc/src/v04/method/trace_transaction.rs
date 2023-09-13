use pathfinder_common::{BlockId, TransactionHash};
use pathfinder_executor::CallError;
use serde::{Deserialize, Serialize};

use crate::{context::RpcContext, executor::ExecutionStateError, map_gateway_transaction};

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceTrasactionInput {
    transaction_hash: TransactionHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceTransactionOutput(TransactionTrace);

crate::error::generate_rpc_error_subset!(
    TraceTransactionError: InvalidTxnHash,
    NoTraceAvailable
);

impl From<ExecutionStateError> for TraceTransactionError {
    fn from(value: ExecutionStateError) -> Self {
        match value {
            ExecutionStateError::BlockNotFound => Self::NoTraceAvailable,
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<CallError> for TraceTransactionError {
    fn from(value: CallError) -> Self {
        match value {
            CallError::ContractNotFound | CallError::InvalidMessageSelector => {
                Self::Internal(anyhow::anyhow!("Failed to trase the block's transactions"))
            }
            CallError::Reverted(e) => Self::Internal(anyhow::anyhow!("Transaction reverted: {e}")),
            CallError::Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTrasactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    let transaction = {
        let mut db = context.storage.connection()?;
        let tx = db.transaction()?;

        let transaction = tx
            .transaction(input.transaction_hash)?
            .ok_or(TraceTransactionError::InvalidTxnHash)?;

        map_gateway_transaction(transaction, &tx)?
    };

    let execution_state = crate::executor::execution_state(context, BlockId::Latest, None).await?;

    let trace = pathfinder_executor::trace_one(execution_state, transaction)?;

    Ok(TraceTransactionOutput(trace.into()))
}
