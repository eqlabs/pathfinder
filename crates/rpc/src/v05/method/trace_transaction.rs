use anyhow::Context;
use pathfinder_common::{BlockHash, BlockId, TransactionHash};
use pathfinder_executor::{CallError, Transaction};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tokio::task::JoinError;

use crate::{
    compose_executor_transaction,
    context::RpcContext,
    error::{RpcError, TraceError},
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

impl From<JoinError> for TraceTransactionError {
    fn from(e: JoinError) -> Self {
        Self::Internal(anyhow::anyhow!("Join error: {e}"))
    }
}

impl From<anyhow::Error> for TraceTransactionError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<TraceTransactionError> for RpcError {
    fn from(value: TraceTransactionError) -> Self {
        match value {
            TraceTransactionError::InvalidTxnHash => RpcError::InvalidTxnHash,
            TraceTransactionError::NoTraceAvailable(status) => RpcError::NoTraceAvailable(status),
            TraceTransactionError::ContractErrorV05 { revert_error } => {
                RpcError::ContractErrorV05 { revert_error }
            }
            TraceTransactionError::Internal(e) => RpcError::Internal(e),
        }
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    let (transactions, parent_block_hash, gas_price): (Vec<Transaction>, BlockHash, Option<U256>) = {
        let span = tracing::Span::current();

        let storage = context.storage.clone();
        tokio::task::spawn_blocking(move || {
            let _g = span.enter();

            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            let block_hash = tx
                .transaction_block_hash(input.transaction_hash)?
                .ok_or(TraceTransactionError::InvalidTxnHash)?;

            let header = tx.block_header(pathfinder_storage::BlockId::Hash(block_hash))?;

            let parent_block_hash = header
                .as_ref()
                .map(|h| h.parent_hash)
                .ok_or(TraceTransactionError::InvalidTxnHash)?;

            let gas_price: Option<U256> =
                header.as_ref().map(|header| U256::from(header.gas_price.0));

            let (transactions, _): (Vec<_>, Vec<_>) = tx
                .transaction_data_for_block(pathfinder_storage::BlockId::Hash(block_hash))?
                .ok_or(TraceTransactionError::InvalidTxnHash)?
                .into_iter()
                .unzip();

            let transactions = transactions
                .into_iter()
                .map(|transaction| compose_executor_transaction(transaction, &tx))
                .collect::<anyhow::Result<Vec<_>, _>>()?;

            Ok::<_, TraceTransactionError>((transactions, parent_block_hash, gas_price))
        })
        .await
        .context("trace_transaction: fetch & map the transaction")??
    };

    let block_id = BlockId::Hash(parent_block_hash);
    let execution_state = crate::executor::execution_state(context, block_id, gas_price).await?;

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
