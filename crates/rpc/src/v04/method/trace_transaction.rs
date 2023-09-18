use pathfinder_common::{BlockId, TransactionHash};
use pathfinder_executor::{CallError, Transaction};
use serde::{Deserialize, Serialize};
use tokio::task::JoinError;

use crate::{compose_executor_transaction, context::RpcContext, executor::ExecutionStateError};

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceTransactionInput {
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
                Self::Internal(anyhow::anyhow!("Failed to trace the block's transactions"))
            }
            CallError::Reverted(e) => Self::Internal(anyhow::anyhow!("Transaction reverted: {e}")),
            CallError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<JoinError> for TraceTransactionError {
    fn from(e: JoinError) -> Self {
        Self::Internal(anyhow::anyhow!("Join error: {e}"))
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    let transactions: Vec<(TransactionHash, Transaction)> = {
        let mut db = context.storage.connection()?;
        tokio::task::spawn_blocking(move || {
            let tx = db.transaction()?;

            let block_hash = tx
                .transaction_block_hash(input.transaction_hash)?
                .ok_or(TraceTransactionError::InvalidTxnHash)?;

            let (transactions, _): (Vec<_>, Vec<_>) = tx
                .transaction_data_for_block(pathfinder_storage::BlockId::Hash(block_hash))?
                .ok_or(TraceTransactionError::InvalidTxnHash)?
                .into_iter()
                .unzip();

            let hashes = transactions.iter().map(|tx| tx.hash()).collect::<Vec<_>>();

            let transactions = transactions
                .into_iter()
                .map(|transaction| compose_executor_transaction(transaction, &tx))
                .collect::<anyhow::Result<Vec<_>, _>>()?;

            Ok::<_, TraceTransactionError>(
                hashes.into_iter().zip(transactions.into_iter()).collect(),
            )
        })
        .await??
    };

    let execution_state = crate::executor::execution_state(context, BlockId::Latest, None).await?;

    let trace = tokio::task::spawn_blocking(move || {
        pathfinder_executor::trace_one(execution_state, transactions, input.transaction_hash)
    })
    .await??;

    Ok(TraceTransactionOutput(trace.into()))
}

#[cfg(test)]
pub mod tests {
    use super::super::trace_block_transactions::tests::setup_trace_test;
    use super::*;

    #[tokio::test]
    async fn test_single_transaction() -> anyhow::Result<()> {
        let (storage, block, expected) = setup_trace_test()?;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = TraceTransactionInput {
            transaction_hash: block.transactions[0].hash(),
        };
        let output = trace_transaction(context, input).await.unwrap();
        let expected = TraceTransactionOutput(expected);

        pretty_assertions::assert_eq!(output, expected);
        Ok(())
    }
}
