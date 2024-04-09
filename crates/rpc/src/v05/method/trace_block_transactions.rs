use anyhow::Context;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockId, TransactionHash};
use pathfinder_executor::{ExecutionState, TraceCache, TransactionExecutionError};
use serde::{Deserialize, Serialize};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::trace::TransactionTrace as GatewayTxTrace;

use super::simulate_transactions::dto::TransactionTrace;
use crate::executor::VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY;
use crate::v05::method::simulate_transactions::dto::{
    DeclareTxnTrace, DeployAccountTxnTrace, ExecuteInvocation, InvokeTxnTrace, L1HandlerTxnTrace,
};
use crate::{compose_executor_transaction, context::RpcContext, executor::ExecutionStateError};

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceBlockTransactionsInput {
    pub block_id: BlockId,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct Trace {
    pub transaction_hash: TransactionHash,
    pub trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceBlockTransactionsOutput(pub Vec<Trace>);

#[derive(Debug)]
pub enum TraceBlockTransactionsError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
    ContractErrorV05 { revert_error: String },
}

impl From<anyhow::Error> for TraceBlockTransactionsError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}

impl From<TraceBlockTransactionsError> for crate::error::ApplicationError {
    fn from(value: TraceBlockTransactionsError) -> Self {
        match value {
            TraceBlockTransactionsError::Internal(e) => Self::Internal(e),
            TraceBlockTransactionsError::BlockNotFound => Self::BlockNotFound,
            TraceBlockTransactionsError::ContractErrorV05 { revert_error } => {
                Self::ContractErrorV05 { revert_error }
            }
            TraceBlockTransactionsError::Custom(e) => Self::Custom(e),
        }
    }
}

impl From<ExecutionStateError> for TraceBlockTransactionsError {
    fn from(value: ExecutionStateError) -> Self {
        match value {
            ExecutionStateError::BlockNotFound => Self::BlockNotFound,
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<TransactionExecutionError> for TraceBlockTransactionsError {
    fn from(value: TransactionExecutionError) -> Self {
        use TransactionExecutionError::*;
        match value {
            ExecutionError {
                transaction_index,
                error,
            } => Self::Custom(anyhow::anyhow!(
                "Execution error at transaction index {}: {}",
                transaction_index,
                error
            )),
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

pub(crate) fn map_gateway_trace(
    transaction: Transaction,
    trace: GatewayTxTrace,
) -> TransactionTrace {
    use pathfinder_common::transaction::TransactionVariant;
    match transaction.variant {
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeclareV3(_) => TransactionTrace::Declare(DeclareTxnTrace {
            fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            validate_invocation: trace.validate_invocation.map(Into::into),
            state_diff: None,
        }),
        TransactionVariant::Deploy(_) => TransactionTrace::DeployAccount(DeployAccountTxnTrace {
            constructor_invocation: trace.function_invocation.map(Into::into),
            fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            validate_invocation: trace.validate_invocation.map(Into::into),
            state_diff: None,
        }),
        TransactionVariant::DeployAccountV1(_) | TransactionVariant::DeployAccountV3(_) => {
            TransactionTrace::DeployAccount(DeployAccountTxnTrace {
                constructor_invocation: trace.function_invocation.map(Into::into),
                fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
                validate_invocation: trace.validate_invocation.map(Into::into),
                state_diff: None,
            })
        }
        TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_)
        | TransactionVariant::InvokeV3(_) => TransactionTrace::Invoke(InvokeTxnTrace {
            execute_invocation: if let Some(revert_reason) = trace.revert_error {
                ExecuteInvocation::RevertedReason { revert_reason }
            } else {
                trace
                    .function_invocation
                    .map(|invocation| ExecuteInvocation::FunctionInvocation(invocation.into()))
                    .unwrap_or_else(|| ExecuteInvocation::Empty)
            },
            fee_transfer_invocation: trace.fee_transfer_invocation.map(Into::into),
            validate_invocation: trace.validate_invocation.map(Into::into),
            state_diff: None,
        }),
        TransactionVariant::L1Handler(_) => TransactionTrace::L1Handler(L1HandlerTxnTrace {
            function_invocation: trace.function_invocation.map(Into::into),
            state_diff: None,
        }),
    }
}

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    enum LocalExecution {
        Success(Vec<Trace>),
        Unsupported(Vec<Transaction>),
    }

    let span = tracing::Span::current();

    let storage = context.storage.clone();
    let traces = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let db = db.transaction()?;

        let (header, transactions, cache) = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                let header = pending.header();
                let transactions = pending.block.transactions.clone();

                (
                    header,
                    transactions,
                    // Can't use caching for pending blocks since they have no block hash.
                    TraceCache::default(),
                )
            }
            other => {
                let block_id = other.try_into().expect("Only pending should fail");
                let header = db
                    .block_header(block_id)?
                    .ok_or(TraceBlockTransactionsError::BlockNotFound)?;

                let transactions = db
                    .transactions_for_block(block_id)?
                    .context("Transaction data missing")?
                    .into_iter()
                    .map(Into::into)
                    .collect();

                (header, transactions, context.cache.clone())
            }
        };

        if header.starknet_version
            < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY
        {
            match input.block_id {
                BlockId::Pending => {
                    return Err(TraceBlockTransactionsError::Internal(anyhow::anyhow!(
                        "Traces are not supported for pending blocks by the feeder gateway"
                    )))
                }
                _ => {
                    return Ok::<_, TraceBlockTransactionsError>(LocalExecution::Unsupported(
                        transactions,
                    ))
                }
            }
        }

        let transactions = transactions
            .iter()
            .map(|transaction| compose_executor_transaction(transaction, &db))
            .collect::<Result<Vec<_>, _>>()?;

        let hash = header.hash;
        let state = ExecutionState::trace(&db, context.chain_id, header, None);
        let traces = pathfinder_executor::trace(state, cache, hash, transactions, true, true)?;

        let result = traces
            .into_iter()
            .map(|(hash, trace)| Trace {
                transaction_hash: hash,
                trace_root: trace.into(),
            })
            .collect();

        Ok(LocalExecution::Success(result))
    })
    .await
    .context("trace_block_transactions: fetch block & transactions")??;

    let transactions = match traces {
        LocalExecution::Success(traces) => return Ok(TraceBlockTransactionsOutput(traces)),
        LocalExecution::Unsupported(transactions) => transactions,
    };

    context
        .sequencer
        .block_traces(input.block_id)
        .await
        .context("Forwarding to feeder gateway")
        .map_err(Into::into)
        .map(|trace| {
            TraceBlockTransactionsOutput(
                trace
                    .traces
                    .into_iter()
                    .zip(transactions.into_iter())
                    .map(|(trace, tx)| {
                        let transaction_hash = tx.hash;
                        let trace_root = map_gateway_trace(tx, trace);

                        Trace {
                            transaction_hash,
                            trace_root,
                        }
                    })
                    .collect(),
            )
        })
}

#[cfg(test)]
pub(crate) mod tests {
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::transaction::Transaction;
    use pathfinder_common::{
        block_hash, felt, BlockHeader, GasPrice, SierraHash, TransactionIndex,
    };
    use starknet_gateway_types::reply::{GasPrices, L1DataAvailabilityMode};

    use super::*;

    pub(crate) async fn setup_multi_tx_trace_test(
    ) -> anyhow::Result<(RpcContext, BlockHeader, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::fixtures;
        use super::super::simulate_transactions::tests::setup_storage;

        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage().await;
        let context = RpcContext::for_tests().with_storage(storage.clone());

        let transactions = vec![
            fixtures::input::declare(account_contract_address).into_common(context.chain_id),
            fixtures::input::universal_deployer(
                account_contract_address,
                universal_deployer_address,
            )
            .into_common(context.chain_id),
            fixtures::input::invoke(account_contract_address).into_common(context.chain_id),
        ];

        let traces = vec![
            fixtures::expected_output::declare(account_contract_address, &last_block_header)
                .transaction_trace,
            fixtures::expected_output::universal_deployer(
                account_contract_address,
                &last_block_header,
                universal_deployer_address,
            )
            .transaction_trace,
            fixtures::expected_output::invoke(
                account_contract_address,
                &last_block_header,
                test_storage_value,
            )
            .transaction_trace,
        ];

        let next_block_header = {
            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            tx.insert_sierra_class(
                &SierraHash(fixtures::SIERRA_HASH.0),
                fixtures::SIERRA_DEFINITION,
                &fixtures::CASM_HASH,
                fixtures::CASM_DEFINITION,
            )?;

            let next_block_header = BlockHeader::builder()
                .with_number(last_block_header.number + 1)
                .with_eth_l1_gas_price(GasPrice(1))
                .with_parent_hash(last_block_header.hash)
                .with_starknet_version(last_block_header.starknet_version)
                .with_sequencer_address(last_block_header.sequencer_address)
                .with_timestamp(last_block_header.timestamp)
                .finalize_with_hash(block_hash!("0x1"));
            tx.insert_block_header(&next_block_header)?;

            let dummy_receipt: Receipt = Receipt {
                transaction_hash: TransactionHash(felt!("0x1")),
                transaction_index: TransactionIndex::new_or_panic(0),
                ..Default::default()
            };
            tx.insert_transaction_data(
                next_block_header.number,
                transactions
                    .iter()
                    .cloned()
                    .map(|t| pathfinder_storage::TransactionData {
                        transaction: t,
                        receipt: Some(dummy_receipt.clone()),
                        events: Some(vec![]),
                    })
                    .collect::<Vec<_>>()
                    .as_slice(),
            )?;
            tx.commit()?;

            next_block_header
        };

        let traces = transactions
            .into_iter()
            .map(|t| t.hash)
            .zip(traces.into_iter())
            .map(|(hash, trace)| Trace {
                transaction_hash: hash,
                trace_root: trace,
            })
            .collect();

        Ok((context, next_block_header, traces))
    }

    #[tokio::test]
    async fn test_multiple_transactions() -> anyhow::Result<()> {
        let (context, next_block_header, traces) = setup_multi_tx_trace_test().await?;

        let input = TraceBlockTransactionsInput {
            block_id: next_block_header.hash.into(),
        };
        let output = trace_block_transactions(context, input).await.unwrap();
        let expected = TraceBlockTransactionsOutput(traces);

        pretty_assertions_sorted::assert_eq!(output, expected);
        Ok(())
    }

    pub(crate) async fn setup_multi_tx_trace_pending_test(
    ) -> anyhow::Result<(RpcContext, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::fixtures;
        use super::super::simulate_transactions::tests::setup_storage;

        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage().await;
        let context = RpcContext::for_tests().with_storage(storage.clone());

        let transactions: Vec<Transaction> = vec![
            fixtures::input::declare(account_contract_address).into_common(context.chain_id),
            fixtures::input::universal_deployer(
                account_contract_address,
                universal_deployer_address,
            )
            .into_common(context.chain_id),
            fixtures::input::invoke(account_contract_address).into_common(context.chain_id),
        ];

        let traces = vec![
            fixtures::expected_output::declare(account_contract_address, &last_block_header)
                .transaction_trace,
            fixtures::expected_output::universal_deployer(
                account_contract_address,
                &last_block_header,
                universal_deployer_address,
            )
            .transaction_trace,
            fixtures::expected_output::invoke(
                account_contract_address,
                &last_block_header,
                test_storage_value,
            )
            .transaction_trace,
        ];

        let pending_block = {
            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            tx.insert_sierra_class(
                &SierraHash(fixtures::SIERRA_HASH.0),
                fixtures::SIERRA_DEFINITION,
                &fixtures::CASM_HASH,
                fixtures::CASM_DEFINITION,
            )?;

            let dummy_receipt = Receipt {
                transaction_hash: TransactionHash(felt!("0x1")),
                transaction_index: TransactionIndex::new_or_panic(0),
                ..Default::default()
            };

            let transaction_receipts = vec![
                (dummy_receipt.clone(), vec![]),
                (dummy_receipt.clone(), vec![]),
                (dummy_receipt, vec![]),
            ];

            let pending_block = starknet_gateway_types::reply::PendingBlock {
                l1_gas_price: GasPrices {
                    price_in_wei: GasPrice(1),
                    price_in_fri: GasPrice(1),
                },
                l1_data_gas_price: GasPrices {
                    price_in_wei: GasPrice(1),
                    price_in_fri: GasPrice(1),
                },
                parent_hash: last_block_header.hash,
                sequencer_address: last_block_header.sequencer_address,
                status: starknet_gateway_types::reply::Status::Pending,
                timestamp: last_block_header.timestamp,
                transaction_receipts,
                transactions: transactions.iter().cloned().map(Into::into).collect(),
                starknet_version: last_block_header.starknet_version,
                l1_da_mode: L1DataAvailabilityMode::Calldata,
            };

            tx.commit()?;

            pending_block
        };

        let pending_data = crate::pending::PendingData {
            block: pending_block.into(),
            state_update: Default::default(),
            number: last_block_header.number + 1,
        };

        let (tx, rx) = tokio::sync::watch::channel(Default::default());
        tx.send(pending_data).unwrap();

        let context = context.with_pending_data(rx);

        let traces = vec![
            Trace {
                transaction_hash: transactions[0].hash,
                trace_root: traces[0].clone(),
            },
            Trace {
                transaction_hash: transactions[1].hash,
                trace_root: traces[1].clone(),
            },
            Trace {
                transaction_hash: transactions[2].hash,
                trace_root: traces[2].clone(),
            },
        ];

        Ok((context, traces))
    }

    #[tokio::test]
    async fn test_multiple_pending_transactions() -> anyhow::Result<()> {
        let (context, traces) = setup_multi_tx_trace_pending_test().await?;

        let input = TraceBlockTransactionsInput {
            block_id: BlockId::Pending,
        };
        let output = trace_block_transactions(context, input).await.unwrap();
        let expected = TraceBlockTransactionsOutput(traces);

        pretty_assertions_sorted::assert_eq!(output, expected);
        Ok(())
    }
}
