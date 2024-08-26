use anyhow::Context;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::TransactionHash;
use pathfinder_executor::{ExecutionState, TraceCache, TransactionExecutionError};
use serde::{Deserialize, Serialize};
use starknet_gateway_client::GatewayApi;

use super::simulate_transactions::dto::TransactionTrace;
use crate::compose_executor_transaction;
use crate::context::RpcContext;
use crate::error::{ApplicationError, TraceError};
use crate::executor::{
    ExecutionStateError,
    VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY,
};
use crate::v06::method::trace_block_transactions::map_gateway_trace;

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

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    trace_transaction_impl(context, input).await.map(|mut x| {
        x.0.with_v06_format();
        x
    })
}

pub async fn trace_transaction_impl(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    #[allow(clippy::large_enum_variant)]
    enum LocalExecution {
        Success(TransactionTrace),
        Unsupported(Transaction),
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
                    TraceCache::default(),
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
            let state = ExecutionState::trace(
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
                    Ok(LocalExecution::Success(trace.try_into()?))
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
        LocalExecution::Success(trace) => return Ok(TraceTransactionOutput(trace)),
        LocalExecution::Unsupported(tx) => tx,
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
    use pathfinder_common::{block_hash, transaction_hash, BlockHeader, Chain, SequencerAddress};
    use pathfinder_crypto::Felt;

    use super::super::trace_block_transactions::tests::{
        setup_multi_tx_trace_pending_test,
        setup_multi_tx_trace_test,
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

    /// Test that tracing succeeds for a block that is not backwards-compatible
    /// with blockifier.
    #[tokio::test]
    async fn mainnet_blockifier_backwards_incompatible_transaction_tracing() {
        let context = RpcContext::for_tests_on(Chain::Mainnet);
        let mut connection = context.storage.connection().unwrap();
        let transaction = connection.transaction().unwrap();
        let block: starknet_gateway_types::reply::Block =
            serde_json::from_str(include_str!("../../../fixtures/mainnet-619596.json")).unwrap();
        let transaction_count = block.transactions.len();
        let event_count = block
            .transaction_receipts
            .iter()
            .map(|(_, events)| events.len())
            .sum();
        let header = BlockHeader {
            hash: block.block_hash,
            parent_hash: block.parent_block_hash,
            number: block.block_number,
            timestamp: block.timestamp,
            eth_l1_gas_price: block.l1_gas_price.price_in_wei,
            strk_l1_gas_price: block.l1_gas_price.price_in_fri,
            eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei,
            strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri,
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(Felt::ZERO)),
            starknet_version: block.starknet_version,
            class_commitment: Default::default(),
            event_commitment: Default::default(),
            state_commitment: Default::default(),
            storage_commitment: Default::default(),
            transaction_commitment: Default::default(),
            transaction_count,
            event_count,
            l1_da_mode: block.l1_da_mode.into(),
            receipt_commitment: Default::default(),
            state_diff_commitment: Default::default(),
            state_diff_length: 0,
        };
        transaction
            .insert_block_header(&BlockHeader {
                number: block.block_number - 1,
                hash: block.parent_block_hash,
                ..header.clone()
            })
            .unwrap();
        transaction
            .insert_block_header(&BlockHeader {
                number: block.block_number - 10,
                hash: block_hash!("0x1"),
                ..header.clone()
            })
            .unwrap();
        transaction.insert_block_header(&header).unwrap();
        let (transactions_data, events_data) = block
            .transactions
            .into_iter()
            .zip(block.transaction_receipts.into_iter())
            .map(|(tx, (receipt, events))| ((tx, receipt), events))
            .unzip::<_, _, Vec<_>, Vec<_>>();
        transaction
            .insert_transaction_data(header.number, &transactions_data, Some(&events_data))
            .unwrap();
        transaction.commit().unwrap();

        // The tracing succeeds.
        trace_transaction(
            context.clone(),
            TraceTransactionInput {
                transaction_hash: transaction_hash!(
                    "0x62c7c8b228f756b3a4ca2c6a7c5488ee2ccb7dd1ac2ec9e657f0292d150a365"
                ),
            },
        )
        .await
        .unwrap();

        // Tracing a second time succeeds as well.
        trace_transaction(
            context.clone(),
            TraceTransactionInput {
                transaction_hash: transaction_hash!(
                    "0x62c7c8b228f756b3a4ca2c6a7c5488ee2ccb7dd1ac2ec9e657f0292d150a365"
                ),
            },
        )
        .await
        .unwrap();
    }
}
