use anyhow::Context;
use pathfinder_executor::TransactionExecutionError;
use starknet_gateway_client::GatewayApi;

use crate::compose_executor_transaction;
use crate::context::RpcContext;
use crate::error::{ApplicationError, TraceError};
use crate::executor::{
    ExecutionStateError,
    VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY,
};
use crate::method::trace_block_transactions::map_gateway_trace;
use crate::v06::method::trace_transaction as v06;

#[derive(Debug)]
pub struct Output {
    trace: pathfinder_executor::types::TransactionTrace,
    include_state_diff: bool,
}

pub async fn trace_transaction(
    context: RpcContext,
    input: v06::TraceTransactionInput,
) -> Result<Output, TraceTransactionError> {
    #[allow(clippy::large_enum_variant)]
    enum LocalExecution {
        Success(pathfinder_executor::types::TransactionTrace),
        Unsupported(pathfinder_common::transaction::Transaction),
    }

    let span = tracing::Span::current();
    let local =
        tokio::task::spawn_blocking(move || -> Result<LocalExecution, TraceTransactionError> {
            let _g = span.enter();

            let mut db = context
                .execution_storage
                .connection()
                .context("Creating database connection")?;
            let db = db.transaction().context("Creating database transaction")?;

            // Find the transaction's block.
            let pending = context
                .pending_data
                .get(&db)
                .context("Querying pending data")?;

            let (header, transactions, cache) = if let Some(pending_tx) = pending
                .block
                .transactions
                .iter()
                .find(|tx| tx.hash == input.transaction_hash)
            {
                let header = pending.header();

                if header.starknet_version
                    < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY
                {
                    return Ok(LocalExecution::Unsupported(pending_tx.clone()));
                }

                (
                    header,
                    pending.block.transactions.clone(),
                    // Can't use the cache for pending blocks since they have no block hash.
                    pathfinder_executor::TraceCache::default(),
                )
            } else {
                let block_hash = db
                    .transaction_block_hash(input.transaction_hash)?
                    .ok_or(TraceTransactionError::TxnHashNotFound)?;

                let header = db
                    .block_header(block_hash.into())
                    .context("Fetching block header")?
                    .context("Block header is missing")?;

                if header.starknet_version
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
                    .context("Block transactions missing")?
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<_>>();

                (header, transactions.clone(), context.cache.clone())
            };

            let hash = header.hash;
            let state = pathfinder_executor::ExecutionState::trace(
                &db,
                context.chain_id,
                header,
                None,
                context.config.custom_versioned_constants,
            );

            let executor_transactions = transactions
                .iter()
                .map(|transaction| compose_executor_transaction(transaction, &db))
                .collect::<Result<Vec<_>, _>>()?;

            match pathfinder_executor::trace(state, cache, hash, executor_transactions) {
                Ok(txs) => {
                    let trace = txs
                        .into_iter()
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
                        })?;
                    Ok(LocalExecution::Success(trace))
                }
                Err(TransactionExecutionError::ExecutionError { .. }) => {
                    Ok(LocalExecution::Unsupported(
                        transactions
                            .into_iter()
                            .find(|tx| tx.hash == input.transaction_hash)
                            .unwrap()
                            .clone(),
                    ))
                }
                Err(e) => Err(e.into()),
            }
        })
        .await
        .context("trace_transaction: execution")??;

    let transaction = match local {
        LocalExecution::Success(trace) => {
            return Ok(Output {
                trace,
                include_state_diff: true,
            })
        }
        LocalExecution::Unsupported(tx) => tx,
    };

    let trace = context
        .sequencer
        .transaction_trace(input.transaction_hash)
        .await
        .context("Proxying call to feeder gateway")?;

    let trace = map_gateway_trace(transaction, trace)?;

    Ok(Output {
        trace,
        // State diffs are not available for traces fetched from the gateway.
        include_state_diff: false,
    })
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        crate::dto::TransactionTrace {
            trace: &self.trace,
            include_state_diff: self.include_state_diff,
        }
        .serialize(serializer)
    }
}

#[derive(Debug)]
pub enum TraceTransactionError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    TxnHashNotFound,
    NoTraceAvailable(TraceError),
    ContractError { revert_error: String },
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

impl From<TraceTransactionError> for ApplicationError {
    fn from(value: TraceTransactionError) -> Self {
        match value {
            TraceTransactionError::TxnHashNotFound => ApplicationError::TxnHashNotFound,
            TraceTransactionError::NoTraceAvailable(status) => {
                ApplicationError::NoTraceAvailable(status)
            }
            TraceTransactionError::ContractError { revert_error } => {
                ApplicationError::ContractError {
                    revert_error: Some(revert_error),
                }
            }
            TraceTransactionError::Internal(e) => ApplicationError::Internal(e),
            TraceTransactionError::Custom(e) => ApplicationError::Custom(e),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::super::trace_block_transactions::tests::{
        setup_multi_tx_trace_pending_test,
        setup_multi_tx_trace_test,
    };
    use super::v06::{TraceTransactionInput, TraceTransactionOutput};
    use super::*;
    use crate::dto::serialize::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[tokio::test]
    async fn test_multiple_transactions() -> anyhow::Result<()> {
        let (context, _, traces) = setup_multi_tx_trace_test().await?;

        for trace in traces {
            let input = TraceTransactionInput {
                transaction_hash: trace.transaction_hash,
            };
            let output = trace_transaction(context.clone(), input).await.unwrap();
            let expected = TraceTransactionOutput(trace.trace_root);
            pretty_assertions_sorted::assert_eq!(
                output
                    .serialize(Serializer {
                        version: RpcVersion::V06
                    })
                    .unwrap(),
                serde_json::to_value(expected).unwrap()
            );
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
            pretty_assertions_sorted::assert_eq!(
                output
                    .serialize(Serializer {
                        version: RpcVersion::V06
                    })
                    .unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }

        Ok(())
    }
}
