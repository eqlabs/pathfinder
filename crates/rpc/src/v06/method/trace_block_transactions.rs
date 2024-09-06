use anyhow::Context;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockId, TransactionHash};
use pathfinder_executor::{ExecutionState, TraceCache, TransactionExecutionError};
use serde::{Deserialize, Serialize};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::trace::TransactionTrace as GatewayTxTrace;

use super::simulate_transactions::dto::TransactionTrace;
use crate::compose_executor_transaction;
use crate::context::RpcContext;
use crate::executor::{
    ExecutionStateError,
    VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY,
};
use crate::v06::method::simulate_transactions::dto::{
    DeclareTxnTrace,
    DeployAccountTxnTrace,
    ExecuteInvocation,
    ExecutionResources,
    FunctionInvocation,
    InvokeTxnTrace,
    L1HandlerTxnTrace,
};

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct TraceBlockTransactionsInput {
    pub block_id: BlockId,
}

impl crate::dto::DeserializeForVersion for TraceBlockTransactionsInput {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_serde()
    }
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
pub struct Trace {
    pub transaction_hash: TransactionHash,
    pub trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq, Clone)]
pub struct TraceBlockTransactionsOutput(pub Vec<Trace>);

#[derive(Debug)]
pub enum TraceBlockTransactionsError {
    Internal(anyhow::Error),
    Custom(anyhow::Error),
    BlockNotFound,
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
                "Transaction execution failed at index {}: {}",
                transaction_index,
                error
            )),
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
        }
    }
}

impl From<TraceConversionError> for TraceBlockTransactionsError {
    fn from(value: TraceConversionError) -> Self {
        Self::Custom(anyhow::anyhow!(value.0))
    }
}

pub(crate) struct TraceConversionError(pub &'static str);

pub(crate) fn map_gateway_trace(
    transaction: Transaction,
    trace: GatewayTxTrace,
) -> Result<TransactionTrace, TraceConversionError> {
    let fee_transfer_invocation = trace.fee_transfer_invocation.map(Into::into);
    let validate_invocation = trace.validate_invocation.map(Into::into);
    let function_invocation = trace.function_invocation.map(Into::into);
    let state_diff = None;

    let computation_resources = validate_invocation
        .as_ref()
        .map(|i: &FunctionInvocation| i.execution_resources.clone())
        .unwrap_or_default()
        + function_invocation
            .as_ref()
            .map(|i: &FunctionInvocation| i.execution_resources.clone())
            .unwrap_or_default()
        + fee_transfer_invocation
            .as_ref()
            .map(|i: &FunctionInvocation| i.execution_resources.clone())
            .unwrap_or_default();
    let execution_resources = Some(ExecutionResources {
        computation_resources,
        // These values are not available in the gateway trace.
        data_availability: Default::default(),
    });

    use pathfinder_common::transaction::TransactionVariant;

    Ok(match transaction.variant {
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeclareV3(_) => TransactionTrace::Declare(DeclareTxnTrace {
            fee_transfer_invocation,
            validate_invocation,
            state_diff,
            execution_resources,
        }),
        TransactionVariant::DeployAccountV1(_)
        | TransactionVariant::DeployAccountV3(_)
        | TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_) => {
            TransactionTrace::DeployAccount(DeployAccountTxnTrace {
                constructor_invocation: function_invocation.ok_or(TraceConversionError(
                    "constructor_invocation is missing from trace response",
                ))?,
                fee_transfer_invocation,
                validate_invocation,
                state_diff,
                execution_resources,
            })
        }
        TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_)
        | TransactionVariant::InvokeV3(_) => TransactionTrace::Invoke(InvokeTxnTrace {
            execute_invocation: if let Some(revert_reason) = trace.revert_error {
                ExecuteInvocation::RevertedReason { revert_reason }
            } else {
                function_invocation
                    .map(ExecuteInvocation::FunctionInvocation)
                    .unwrap_or_else(|| ExecuteInvocation::Empty)
            },
            fee_transfer_invocation,
            validate_invocation,
            state_diff,
            execution_resources,
        }),
        TransactionVariant::L1Handler(_) => TransactionTrace::L1Handler(L1HandlerTxnTrace {
            function_invocation: function_invocation.ok_or(TraceConversionError(
                "function_invocation is missing from trace response",
            ))?,
            state_diff,
            execution_resources,
        }),
    })
}

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    trace_block_transactions_impl(context, input)
        .await
        .map(|mut x| {
            x.0.iter_mut().for_each(|y| y.trace_root.with_v06_format());
            x
        })
}

pub async fn trace_block_transactions_impl(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    enum LocalExecution {
        Success(Vec<Trace>),
        Unsupported(Vec<Transaction>),
    }

    let span = tracing::Span::current();

    let storage = context.execution_storage.clone();
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
                    // Can't use the cache for pending blocks since they have no block hash.
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
                    .collect::<Vec<_>>();

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

        let executor_transactions = transactions
            .iter()
            .map(|transaction| compose_executor_transaction(transaction, &db))
            .collect::<Result<Vec<_>, _>>()?;

        let hash = header.hash;
        let state = ExecutionState::trace(
            &db,
            context.chain_id,
            header,
            None,
            context.config.custom_versioned_constants,
        );
        let traces = match pathfinder_executor::trace(state, cache, hash, executor_transactions) {
            Ok(traces) => traces,
            Err(TransactionExecutionError::ExecutionError { .. }) => {
                return Ok(LocalExecution::Unsupported(transactions))
            }
            Err(e) => return Err(e.into()),
        };

        let result = traces
            .into_iter()
            .map(|(hash, trace)| {
                Ok(Trace {
                    transaction_hash: hash,
                    trace_root: trace.try_into()?,
                })
            })
            .collect::<Result<Vec<_>, TraceBlockTransactionsError>>()?;

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
        .map_err(TraceBlockTransactionsError::from)
        .map(|trace| {
            Ok(TraceBlockTransactionsOutput(
                trace
                    .traces
                    .into_iter()
                    .zip(transactions.into_iter())
                    .map(|(trace, tx)| {
                        let transaction_hash = tx.hash;
                        let trace_root = map_gateway_trace(tx, trace)?;

                        Ok(Trace {
                            transaction_hash,
                            trace_root,
                        })
                    })
                    .collect::<Result<Vec<_>, TraceBlockTransactionsError>>()?,
            ))
        })?
}

#[cfg(test)]
pub(crate) mod tests {
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::{
        block_hash,
        felt,
        BlockHeader,
        Chain,
        GasPrice,
        SequencerAddress,
        SierraHash,
        StarknetVersion,
        TransactionIndex,
    };
    use pathfinder_crypto::Felt;
    use starknet_gateway_types::reply::{GasPrices, L1DataAvailabilityMode};
    use tokio::task::JoinSet;

    use super::*;

    pub(crate) async fn setup_multi_tx_trace_test(
    ) -> anyhow::Result<(RpcContext, BlockHeader, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::{
            fixtures,
            setup_storage_with_starknet_version,
        };

        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
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
            fixtures::expected_output_0_13_1_1::declare(
                account_contract_address,
                &last_block_header,
            )
            .transaction_trace,
            fixtures::expected_output_0_13_1_1::universal_deployer(
                account_contract_address,
                &last_block_header,
                universal_deployer_address,
            )
            .transaction_trace,
            fixtures::expected_output_0_13_1_1::invoke(
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
                .number(last_block_header.number + 1)
                .eth_l1_gas_price(GasPrice(1))
                .eth_l1_data_gas_price(GasPrice(2))
                .parent_hash(last_block_header.hash)
                .starknet_version(last_block_header.starknet_version)
                .sequencer_address(last_block_header.sequencer_address)
                .timestamp(last_block_header.timestamp)
                .finalize_with_hash(block_hash!("0x1"));
            tx.insert_block_header(&next_block_header)?;

            let dummy_receipt = Receipt {
                transaction_hash: TransactionHash(felt!("0x1")),
                transaction_index: TransactionIndex::new_or_panic(0),
                ..Default::default()
            };
            tx.insert_transaction_data(
                next_block_header.number,
                &[
                    (transactions[0].clone(), dummy_receipt.clone()),
                    (transactions[1].clone(), dummy_receipt.clone()),
                    (transactions[2].clone(), dummy_receipt.clone()),
                ],
                Some(&[vec![], vec![], vec![]]),
            )?;
            tx.commit()?;

            next_block_header
        };

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

    /// Test that multiple requests for the same block return correctly. This
    /// checks that the trace request coalescing doesn't do anything
    /// unexpected.
    #[tokio::test]
    async fn test_request_coalescing() -> anyhow::Result<()> {
        const NUM_REQUESTS: usize = 1000;

        let (context, next_block_header, traces) = setup_multi_tx_trace_test().await?;

        let input = TraceBlockTransactionsInput {
            block_id: next_block_header.hash.into(),
        };
        let mut joins = JoinSet::new();
        for _ in 0..NUM_REQUESTS {
            let input = input.clone();
            let context = context.clone();
            joins.spawn(async move { trace_block_transactions(context, input).await.unwrap() });
        }
        let mut outputs = Vec::new();
        while let Some(output) = joins.join_next().await {
            outputs.push(output.unwrap());
        }
        let expected = vec![TraceBlockTransactionsOutput(traces); NUM_REQUESTS];

        pretty_assertions_sorted::assert_eq!(outputs, expected);
        Ok(())
    }

    pub(crate) async fn setup_multi_tx_trace_pending_test(
    ) -> anyhow::Result<(RpcContext, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::{
            fixtures,
            setup_storage_with_starknet_version,
        };

        let (
            storage,
            last_block_header,
            account_contract_address,
            universal_deployer_address,
            test_storage_value,
        ) = setup_storage_with_starknet_version(StarknetVersion::new(0, 13, 1, 1)).await;
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
            fixtures::expected_output_0_13_1_1::declare(
                account_contract_address,
                &last_block_header,
            )
            .transaction_trace,
            fixtures::expected_output_0_13_1_1::universal_deployer(
                account_contract_address,
                &last_block_header,
                universal_deployer_address,
            )
            .transaction_trace,
            fixtures::expected_output_0_13_1_1::invoke(
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

            let transaction_receipts = vec![(dummy_receipt, vec![]); 3];

            let pending_block = starknet_gateway_types::reply::PendingBlock {
                l1_gas_price: GasPrices {
                    price_in_wei: GasPrice(1),
                    price_in_fri: GasPrice(1),
                },
                l1_data_gas_price: GasPrices {
                    price_in_wei: GasPrice(2),
                    price_in_fri: GasPrice(2),
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
        trace_block_transactions(
            context.clone(),
            TraceBlockTransactionsInput {
                block_id: BlockId::Number(block.block_number),
            },
        )
        .await
        .unwrap();
    }
}
