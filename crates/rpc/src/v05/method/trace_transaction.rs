use anyhow::Context;
use pathfinder_common::{BlockHash, BlockId, GasPrice, TransactionHash};
use pathfinder_executor::CallError;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

use crate::{
    context::RpcContext,
    error::{ApplicationError, TraceError},
    executor::ExecutionStateError,
};

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceTransactionInput {
    pub transaction_hash: TransactionHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceTransactionOutput(pub TransactionTrace);

#[derive(Debug)]
pub enum TraceTransactionError {
    Internal(anyhow::Error),
    InvalidTxnHash,
    NoTraceAvailable(TraceError),
    ContractErrorV05 { revert_error: String },
}

impl From<ExecutionStateError> for TraceTransactionError {
    fn from(value: ExecutionStateError) -> Self {
        match value {
            ExecutionStateError::BlockNotFound => {
                Self::Internal(anyhow::anyhow!("Block not found"))
            }
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<CallError> for TraceTransactionError {
    fn from(value: CallError) -> Self {
        match value {
            CallError::ContractNotFound => Self::Internal(anyhow::anyhow!("Contract not found")),
            CallError::InvalidMessageSelector => {
                Self::Internal(anyhow::anyhow!("Invalid message selector"))
            }
            CallError::Reverted(revert_error) => Self::ContractErrorV05 { revert_error },
            CallError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<anyhow::Error> for TraceTransactionError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<super::trace_block_transactions::TraceBlockTransactionsError> for TraceTransactionError {
    fn from(e: super::trace_block_transactions::TraceBlockTransactionsError) -> Self {
        use super::trace_block_transactions::TraceBlockTransactionsError::*;
        match e {
            Internal(e) => Self::Internal(e),
            BlockNotFound => Self::Internal(anyhow::anyhow!("Block not found")),
            ContractErrorV05 { revert_error } => Self::ContractErrorV05 { revert_error },
        }
    }
}

impl From<TraceTransactionError> for ApplicationError {
    fn from(value: TraceTransactionError) -> Self {
        match value {
            TraceTransactionError::InvalidTxnHash => ApplicationError::InvalidTxnHash,
            TraceTransactionError::NoTraceAvailable(status) => {
                ApplicationError::NoTraceAvailable(status)
            }
            TraceTransactionError::ContractErrorV05 { revert_error } => {
                ApplicationError::ContractErrorV05 { revert_error }
            }
            TraceTransactionError::Internal(e) => ApplicationError::Internal(e),
        }
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    let (transactions, gas_price, parent_block_hash) =
        fetch_transactions(&context, input.transaction_hash).await?;

    let parent_block_id = BlockId::Hash(parent_block_hash);
    let gas_price = Some(U256::from(gas_price.0));
    let execution_state =
        crate::executor::execution_state(context, parent_block_id, gas_price).await?;

    let span = tracing::Span::current();
    let trace = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        pathfinder_executor::trace_one(
            execution_state,
            transactions,
            input.transaction_hash,
            true,
            true,
        )
    })
    .await
    .context("trace_transaction: execution")??;

    Ok(TraceTransactionOutput(trace.into()))
}

async fn fetch_transactions(
    context: &RpcContext,
    transaction_hash: TransactionHash,
) -> Result<(Vec<pathfinder_executor::Transaction>, GasPrice, BlockHash), TraceTransactionError> {
    // Try pending block first
    if let Some(pending) = &context.pending_data {
        if let Some(block) = pending.block().await {
            if block
                .transactions
                .iter()
                .any(|tx| tx.hash() == transaction_hash)
            {
                let storage = context.storage.clone();
                let span = tracing::Span::current();
                return tokio::task::spawn_blocking(move || {
                    let _g = span.enter();
                    super::trace_block_transactions::fetch_pending_transactions(
                        storage,
                        block.as_ref(),
                    )
                    .map_err(Into::into)
                })
                .await
                .context("Fetching pending transactions")?;
            }
        }
    };

    fetch_block_transactions(context.storage.clone(), transaction_hash).await
}

async fn fetch_block_transactions(
    storage: pathfinder_storage::Storage,
    transaction_hash: TransactionHash,
) -> Result<(Vec<pathfinder_executor::Transaction>, GasPrice, BlockHash), TraceTransactionError> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction()?;

        let block_hash = tx
            .transaction_block_hash(transaction_hash)?
            .ok_or(TraceTransactionError::InvalidTxnHash)?;

        super::trace_block_transactions::fetch_block_transactions(&tx, block_hash.into())
            .map_err(Into::into)
    })
    .await
    .context("trace_transaction: fetch & map the transaction")?
}

#[cfg(test)]
pub mod tests {
    use super::super::trace_block_transactions::tests::setup_multi_tx_trace_test;
    use super::*;

    #[tokio::test]
    async fn test_multiple_transactions() -> anyhow::Result<()> {
        let (context, _, traces) = setup_multi_tx_trace_test().await?;

        for trace in traces {
            let input = TraceTransactionInput {
                transaction_hash: trace.transaction_hash,
            };
            let output = trace_transaction(context.clone(), input).await.unwrap();
            let expected = TraceTransactionOutput(trace.trace_root);
            pretty_assertions::assert_eq!(output, expected);
        }

        Ok(())
    }
}
