use anyhow::Context;
use pathfinder_common::TransactionHash;
use pathfinder_executor::{ExecutionState, TransactionExecutionError};
use serde::{Deserialize, Serialize};
use starknet_gateway_client::GatewayApi;

use crate::compose_executor_transaction;
use crate::executor::VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY;
use crate::v06::method::trace_block_transactions::map_gateway_trace;
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
    Custom(anyhow::Error),
    TxnHashNotFound,
    NoTraceAvailable(TraceError),
    ContractErrorV05 { revert_error: String },
}

impl From<ExecutionStateError> for TraceTransactionError {
    fn from(value: ExecutionStateError) -> Self {
        match value {
            ExecutionStateError::BlockNotFound => Self::Custom(anyhow::anyhow!("Block not found")),
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<TransactionExecutionError> for TraceTransactionError {
    fn from(value: TransactionExecutionError) -> Self {
        use TransactionExecutionError::*;
        match value {
            ExecutionError {
                transaction_index,
                error,
            } => Self::Custom(anyhow::anyhow!(
                "Transaction execution failed at index {}: {}",
                transaction_index,
                error
            )),
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
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
            BlockNotFound => Self::Custom(anyhow::anyhow!("Block not found")),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<super::trace_block_transactions::TraceConversionError> for TraceTransactionError {
    fn from(value: super::trace_block_transactions::TraceConversionError) -> Self {
        Self::Custom(anyhow::anyhow!(value.0))
    }
}

impl From<TraceTransactionError> for ApplicationError {
    fn from(value: TraceTransactionError) -> Self {
        match value {
            TraceTransactionError::TxnHashNotFound => ApplicationError::TxnHashNotFound,
            TraceTransactionError::NoTraceAvailable(status) => {
                ApplicationError::NoTraceAvailable(status)
            }
            TraceTransactionError::ContractErrorV05 { revert_error } => {
                ApplicationError::ContractErrorV05 { revert_error }
            }
            TraceTransactionError::Internal(e) => ApplicationError::Internal(e),
            TraceTransactionError::Custom(e) => ApplicationError::Custom(e),
        }
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    #[allow(clippy::large_enum_variant)]
    enum LocalExecution {
        Success(TransactionTrace),
        Unsupported(starknet_gateway_types::reply::transaction::Transaction),
    }

    let span = tracing::Span::current();
    let local = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = context
            .storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        // Find the transaction's block.
        let pending = context
            .pending_data
            .get(&db)
            .context("Querying pending data")?;

        let (header, transactions) = if let Some(pending_tx) = pending
            .block
            .transactions
            .iter()
            .find(|tx| tx.hash() == input.transaction_hash)
        {
            let header = pending.header();

            let starknet_version = header
                .starknet_version
                .parse_as_semver()
                .context("Parsing starknet version")?
                .unwrap_or(semver::Version::new(0, 0, 0));
            if starknet_version
                < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY
            {
                return Ok(LocalExecution::Unsupported(pending_tx.clone()));
            }

            (header, pending.block.transactions.clone())
        } else {
            let block_hash = db
                .transaction_block_hash(input.transaction_hash)?
                .ok_or(TraceTransactionError::TxnHashNotFound)?;

            let header = db
                .block_header(block_hash.into())
                .context("Fetching block header")?
                .context("Block header is missing")?;

            let starknet_version = header
                .starknet_version
                .parse_as_semver()
                .context("Parsing starknet version")?
                .unwrap_or(semver::Version::new(0, 0, 0));
            if starknet_version
                < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY
            {
                let transaction = db
                    .transaction(input.transaction_hash)
                    .context("Fetching transaction data")?
                    .context("Transaction data missing")?;

                return Ok(LocalExecution::Unsupported(transaction));
            }

            let transactions = db
                .transactions_for_block(header.number.into())
                .context("Fetching block transactions")?
                .context("Block transactions missing")?;

            (header, transactions.clone())
        };

        let hash = header.hash;
        let state = ExecutionState::trace(&db, context.chain_id, header, None);

        let transactions = transactions
            .iter()
            .map(|transaction| compose_executor_transaction(transaction, &db))
            .collect::<Result<Vec<_>, _>>()?;

        pathfinder_executor::trace(state, &context.cache, hash, transactions, true, true)
            .map_err(TraceTransactionError::from)
            .and_then(|txs| {
                txs.into_iter()
                    .find_map(|(tx_hash, trace)| {
                        if tx_hash == input.transaction_hash {
                            Some(trace)
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        TraceTransactionError::Internal(anyhow::anyhow!(
                            "Transaction trace missing from block: {}",
                            input.transaction_hash
                        ))
                    })
            })
            .and_then(|x| Ok(LocalExecution::Success(x.try_into()?)))
    })
    .await
    .context("trace_transaction: execution")??;

    let transaction = match local {
        LocalExecution::Success(trace) => return Ok(TraceTransactionOutput(trace)),
        LocalExecution::Unsupported(x) => x,
    };

    let trace = context
        .sequencer
        .transaction_trace(input.transaction_hash)
        .await
        .context("Proxying call to feeder gateway")?;

    let trace = map_gateway_trace(transaction, trace)?;

    Ok(TraceTransactionOutput(trace))
}

#[cfg(test)]
pub mod tests {
    use super::super::trace_block_transactions::tests::{
        setup_multi_tx_trace_pending_test, setup_multi_tx_trace_test,
    };
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
            pretty_assertions_sorted::assert_eq!(output, expected);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_pending_transactions() -> anyhow::Result<()> {
        let (context, traces) = setup_multi_tx_trace_pending_test().await?;

        for trace in traces {
            let input = TraceTransactionInput {
                transaction_hash: trace.transaction_hash,
            };
            let output = trace_transaction(context.clone(), input).await.unwrap();
            let expected = TraceTransactionOutput(trace.trace_root);
            pretty_assertions_sorted::assert_eq!(output, expected);
        }

        Ok(())
    }
}
