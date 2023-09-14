use pathfinder_common::{BlockHash, TransactionHash};
use pathfinder_executor::CallError;
use pathfinder_storage::BlockId;
use serde::{Deserialize, Serialize};

use crate::{context::RpcContext, executor::ExecutionStateError, map_gateway_transaction};

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceBlockTransactionsInput {
    block_hash: BlockHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct Trace {
    transaction_hash: TransactionHash,
    trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceBlockTransactionsOutput(Vec<Trace>);

crate::error::generate_rpc_error_subset!(
    TraceBlockTransactionsError: InvalidBlockHash
);

impl From<ExecutionStateError> for TraceBlockTransactionsError {
    fn from(value: ExecutionStateError) -> Self {
        match value {
            ExecutionStateError::BlockNotFound => Self::InvalidBlockHash,
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<CallError> for TraceBlockTransactionsError {
    fn from(value: CallError) -> Self {
        match value {
            CallError::ContractNotFound | CallError::InvalidMessageSelector => {
                Self::Internal(anyhow::anyhow!("Failed to trase the transaction"))
            }
            CallError::Reverted(e) => Self::Internal(anyhow::anyhow!("Transaction reverted: {e}")),
            CallError::Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    let (hashes, transactions) = {
        let mut db = context.storage.connection()?;
        let tx = db.transaction()?;

        let (transactions, _): (Vec<_>, Vec<_>) = tx
            .transaction_data_for_block(BlockId::Hash(input.block_hash))?
            .ok_or(TraceBlockTransactionsError::InvalidBlockHash)?
            .into_iter()
            .unzip();

        let hashes = transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>();

        let transactions = transactions
            .into_iter()
            .map(|transaction| map_gateway_transaction(transaction, &tx))
            .collect::<anyhow::Result<Vec<_>, _>>()?;

        (hashes, transactions)
    };

    let execution_state =
        crate::executor::execution_state(context, pathfinder_common::BlockId::Latest, None).await?;

    let traces = pathfinder_executor::trace_all(execution_state, transactions)?;

    let result = traces
        .into_iter()
        .zip(hashes.into_iter())
        .map(|(trace, hash)| Trace {
            transaction_hash: hash,
            trace_root: trace.into(),
        })
        .collect();

    Ok(TraceBlockTransactionsOutput(result))
}
