use anyhow::Context;
use pathfinder_common::BlockId;
use pathfinder_executor::TransactionExecutionError;
use starknet_gateway_client::GatewayApi;

use crate::compose_executor_transaction;
use crate::context::RpcContext;
use crate::executor::{
    ExecutionStateError,
    VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY,
};
use crate::v06::method::trace_block_transactions as v06;

pub struct Output {
    traces: Vec<(
        pathfinder_common::TransactionHash,
        pathfinder_executor::types::TransactionTrace,
    )>,
    include_state_diffs: bool,
}

pub async fn trace_block_transactions(
    context: RpcContext,
    input: v06::TraceBlockTransactionsInput,
) -> Result<Output, TraceBlockTransactionsError> {
    enum LocalExecution {
        Success(Output),
        Unsupported(Vec<pathfinder_common::transaction::Transaction>),
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
                    pathfinder_executor::TraceCache::default(),
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
        let state = pathfinder_executor::ExecutionState::trace(
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

        let traces = traces
            .into_iter()
            .map(|(hash, trace)| Ok((hash, trace)))
            .collect::<Result<Vec<_>, TraceBlockTransactionsError>>()?;

        Ok(LocalExecution::Success(Output {
            traces,
            include_state_diffs: true,
        }))
    })
    .await
    .context("trace_block_transactions: fetch block & transactions")??;

    let transactions = match traces {
        LocalExecution::Success(output) => return Ok(output),
        LocalExecution::Unsupported(transactions) => transactions,
    };

    context
        .sequencer
        .block_traces(input.block_id)
        .await
        .context("Forwarding to feeder gateway")
        .map_err(TraceBlockTransactionsError::from)
        .map(|trace| {
            Ok(Output {
                traces: trace
                    .traces
                    .into_iter()
                    .zip(transactions.into_iter())
                    .map(|(trace, tx)| {
                        let transaction_hash = tx.hash;
                        let trace_root = map_gateway_trace(tx, trace)?;

                        Ok((transaction_hash, trace_root))
                    })
                    .collect::<Result<Vec<_>, TraceBlockTransactionsError>>()?,
                // State diffs are not available for traces fetched from the gateway.
                include_state_diffs: false,
            })
        })?
}

pub(crate) fn map_gateway_trace(
    transaction: pathfinder_common::transaction::Transaction,
    trace: starknet_gateway_types::trace::TransactionTrace,
) -> anyhow::Result<pathfinder_executor::types::TransactionTrace> {
    let validate_invocation_resources = trace
        .validate_invocation
        .as_ref()
        .map(|i| i.execution_resources)
        .unwrap_or_default();
    let function_invocation_resources = trace
        .function_invocation
        .as_ref()
        .map(|i| i.execution_resources)
        .unwrap_or_default();
    let fee_transfer_invocation_resources = trace
        .fee_transfer_invocation
        .as_ref()
        .map(|i| i.execution_resources)
        .unwrap_or_default();

    let computation_resources = pathfinder_executor::types::ComputationResources {
        steps: (validate_invocation_resources.n_steps
            + function_invocation_resources.n_steps
            + fee_transfer_invocation_resources.n_steps)
            .try_into()
            .unwrap(),
        memory_holes: (validate_invocation_resources.n_memory_holes
            + function_invocation_resources.n_memory_holes
            + fee_transfer_invocation_resources.n_memory_holes)
            .try_into()
            .unwrap(),
        range_check_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .range_check_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .range_check_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .range_check_builtin)
            .try_into()
            .unwrap(),
        pedersen_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .pedersen_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .pedersen_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .pedersen_builtin)
            .try_into()
            .unwrap(),
        poseidon_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .poseidon_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .poseidon_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .poseidon_builtin)
            .try_into()
            .unwrap(),
        ec_op_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .ec_op_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .ec_op_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .ec_op_builtin)
            .try_into()
            .unwrap(),
        ecdsa_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .ecdsa_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .ecdsa_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .ecdsa_builtin)
            .try_into()
            .unwrap(),
        bitwise_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .bitwise_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .bitwise_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .bitwise_builtin)
            .try_into()
            .unwrap(),
        keccak_builtin_applications: (validate_invocation_resources
            .builtin_instance_counter
            .keccak_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .keccak_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .keccak_builtin)
            .try_into()
            .unwrap(),
        segment_arena_builtin: (validate_invocation_resources
            .builtin_instance_counter
            .segment_arena_builtin
            + function_invocation_resources
                .builtin_instance_counter
                .segment_arena_builtin
            + fee_transfer_invocation_resources
                .builtin_instance_counter
                .segment_arena_builtin)
            .try_into()
            .unwrap(),
    };
    let execution_resources = pathfinder_executor::types::ExecutionResources {
        computation_resources,
        // These values are not available in the gateway trace.
        data_availability: Default::default(),
    };

    use pathfinder_common::transaction::TransactionVariant;

    Ok(match transaction.variant {
        TransactionVariant::DeclareV0(_)
        | TransactionVariant::DeclareV1(_)
        | TransactionVariant::DeclareV2(_)
        | TransactionVariant::DeclareV3(_) => {
            pathfinder_executor::types::TransactionTrace::Declare(
                pathfinder_executor::types::DeclareTransactionTrace {
                    fee_transfer_invocation: trace
                        .fee_transfer_invocation
                        .map(map_gateway_function_invocation)
                        .transpose()?,
                    validate_invocation: trace
                        .validate_invocation
                        .map(map_gateway_function_invocation)
                        .transpose()?,
                    state_diff: Default::default(),
                    execution_resources,
                },
            )
        }
        TransactionVariant::DeployAccountV1(_)
        | TransactionVariant::DeployAccountV3(_)
        | TransactionVariant::DeployV0(_)
        | TransactionVariant::DeployV1(_) => {
            pathfinder_executor::types::TransactionTrace::DeployAccount(
                pathfinder_executor::types::DeployAccountTransactionTrace {
                    constructor_invocation: trace
                        .function_invocation
                        .map(map_gateway_function_invocation)
                        .transpose()?,
                    fee_transfer_invocation: trace
                        .fee_transfer_invocation
                        .map(map_gateway_function_invocation)
                        .transpose()?,
                    validate_invocation: trace
                        .validate_invocation
                        .map(map_gateway_function_invocation)
                        .transpose()?,
                    state_diff: Default::default(),
                    execution_resources,
                },
            )
        }
        TransactionVariant::InvokeV0(_)
        | TransactionVariant::InvokeV1(_)
        | TransactionVariant::InvokeV3(_) => pathfinder_executor::types::TransactionTrace::Invoke(
            pathfinder_executor::types::InvokeTransactionTrace {
                execute_invocation: if let Some(revert_reason) = trace.revert_error {
                    pathfinder_executor::types::ExecuteInvocation::RevertedReason(revert_reason)
                } else {
                    pathfinder_executor::types::ExecuteInvocation::FunctionInvocation(
                        trace
                            .function_invocation
                            .map(map_gateway_function_invocation)
                            .transpose()?,
                    )
                },
                fee_transfer_invocation: trace
                    .fee_transfer_invocation
                    .map(map_gateway_function_invocation)
                    .transpose()?,
                validate_invocation: trace
                    .validate_invocation
                    .map(map_gateway_function_invocation)
                    .transpose()?,
                state_diff: Default::default(),
                execution_resources,
            },
        ),
        TransactionVariant::L1Handler(_) => {
            pathfinder_executor::types::TransactionTrace::L1Handler(
                pathfinder_executor::types::L1HandlerTransactionTrace {
                    function_invocation: trace
                        .function_invocation
                        .map(map_gateway_function_invocation)
                        .transpose()?,
                    state_diff: Default::default(),
                    execution_resources,
                },
            )
        }
    })
}

fn map_gateway_function_invocation(
    invocation: starknet_gateway_types::trace::FunctionInvocation,
) -> anyhow::Result<pathfinder_executor::types::FunctionInvocation> {
    Ok(pathfinder_executor::types::FunctionInvocation {
        calldata: invocation.calldata,
        contract_address: invocation.contract_address,
        selector: invocation
            .selector
            .ok_or_else(|| anyhow::anyhow!("selector is missing from trace response"))?,
        call_type: match invocation
            .call_type
            .ok_or_else(|| anyhow::anyhow!("call_type is missing from trace response"))?
        {
            starknet_gateway_types::trace::CallType::Call => {
                pathfinder_executor::types::CallType::Call
            }
            starknet_gateway_types::trace::CallType::Delegate => {
                pathfinder_executor::types::CallType::Delegate
            }
        },
        caller_address: invocation.caller_address,
        internal_calls: invocation
            .internal_calls
            .into_iter()
            .map(map_gateway_function_invocation)
            .collect::<Result<_, _>>()?,
        class_hash: invocation.class_hash,
        entry_point_type: match invocation
            .entry_point_type
            .ok_or_else(|| anyhow::anyhow!("entry_point_type is missing from trace response"))?
        {
            starknet_gateway_types::trace::EntryPointType::Constructor => {
                pathfinder_executor::types::EntryPointType::Constructor
            }
            starknet_gateway_types::trace::EntryPointType::External => {
                pathfinder_executor::types::EntryPointType::External
            }
            starknet_gateway_types::trace::EntryPointType::L1Handler => {
                pathfinder_executor::types::EntryPointType::L1Handler
            }
        },
        events: invocation
            .events
            .into_iter()
            .map(|ev| pathfinder_executor::types::Event {
                order: ev.order,
                data: ev.data,
                keys: ev.keys,
            })
            .collect(),
        messages: invocation
            .messages
            .into_iter()
            .map(|msg| pathfinder_executor::types::MsgToL1 {
                order: msg.order,
                payload: msg.payload,
                to_address: msg.to_address,
                from_address: invocation.contract_address.0,
            })
            .collect(),
        result: invocation.result,
        computation_resources: map_gateway_computation_resources(invocation.execution_resources),
    })
}

fn map_gateway_computation_resources(
    resources: starknet_gateway_types::reply::transaction::ExecutionResources,
) -> pathfinder_executor::types::ComputationResources {
    pathfinder_executor::types::ComputationResources {
        steps: resources.n_steps.try_into().unwrap(),
        memory_holes: resources.n_memory_holes.try_into().unwrap(),
        range_check_builtin_applications: resources
            .builtin_instance_counter
            .range_check_builtin
            .try_into()
            .unwrap(),
        pedersen_builtin_applications: resources
            .builtin_instance_counter
            .pedersen_builtin
            .try_into()
            .unwrap(),
        poseidon_builtin_applications: resources
            .builtin_instance_counter
            .poseidon_builtin
            .try_into()
            .unwrap(),
        ec_op_builtin_applications: resources
            .builtin_instance_counter
            .ec_op_builtin
            .try_into()
            .unwrap(),
        ecdsa_builtin_applications: resources
            .builtin_instance_counter
            .ecdsa_builtin
            .try_into()
            .unwrap(),
        bitwise_builtin_applications: resources
            .builtin_instance_counter
            .bitwise_builtin
            .try_into()
            .unwrap(),
        keccak_builtin_applications: resources
            .builtin_instance_counter
            .keccak_builtin
            .try_into()
            .unwrap(),
        segment_arena_builtin: resources
            .builtin_instance_counter
            .segment_arena_builtin
            .try_into()
            .unwrap(),
    }
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        serializer.serialize_iter(
            self.traces.len(),
            &mut self.traces.iter().map(|(hash, trace)| Trace {
                transaction_hash: hash,
                transaction_trace: trace,
                include_state_diff: self.include_state_diffs,
            }),
        )
    }
}

struct Trace<'a> {
    transaction_hash: &'a pathfinder_common::TransactionHash,
    transaction_trace: &'a pathfinder_executor::types::TransactionTrace,
    include_state_diff: bool,
}

impl crate::dto::serialize::SerializeForVersion for Trace<'_> {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field(
            "transaction_hash",
            &crate::dto::TxnHash(self.transaction_hash),
        )?;
        serializer.serialize_field(
            "trace_root",
            &crate::dto::TransactionTrace {
                trace: self.transaction_trace,
                include_state_diff: self.include_state_diff,
            },
        )?;
        serializer.end()
    }
}

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

#[cfg(test)]
pub(crate) mod tests {
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::{
        block_hash,
        transaction_hash,
        BlockHeader,
        BlockId,
        GasPrice,
        L1DataAvailabilityMode,
        SierraHash,
        StarknetVersion,
        TransactionIndex,
    };
    use starknet_gateway_types::reply::GasPrices;
    use tokio::task::JoinSet;

    use super::v06::{Trace, TraceBlockTransactionsInput, TraceBlockTransactionsOutput};
    use super::{trace_block_transactions, RpcContext};
    use crate::dto::serialize::{SerializeForVersion, Serializer};
    use crate::v06::method::simulate_transactions::tests::setup_storage_with_starknet_version;
    use crate::RpcVersion;

    pub(crate) async fn setup_multi_tx_trace_test(
    ) -> anyhow::Result<(RpcContext, BlockHeader, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::fixtures;

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
                .with_number(last_block_header.number + 1)
                .with_eth_l1_gas_price(GasPrice(1))
                .with_eth_l1_data_gas_price(GasPrice(2))
                .with_parent_hash(last_block_header.hash)
                .with_starknet_version(last_block_header.starknet_version)
                .with_sequencer_address(last_block_header.sequencer_address)
                .with_timestamp(last_block_header.timestamp)
                .with_starknet_version(StarknetVersion::new(0, 13, 1, 1))
                .with_l1_da_mode(L1DataAvailabilityMode::Blob)
                .finalize_with_hash(block_hash!("0x1"));
            tx.insert_block_header(&next_block_header)?;

            let dummy_receipt = Receipt {
                transaction_hash: transaction_hash!("0x1"),
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

        pretty_assertions_sorted::assert_eq!(
            output
                .serialize(Serializer {
                    version: RpcVersion::V06,
                })
                .unwrap(),
            serde_json::to_value(expected).unwrap()
        );
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
            outputs.push(
                output
                    .unwrap()
                    .serialize(Serializer {
                        version: RpcVersion::V06,
                    })
                    .unwrap(),
            );
        }
        let mut expected = Vec::new();
        for _ in 0..NUM_REQUESTS {
            expected
                .push(serde_json::to_value(TraceBlockTransactionsOutput(traces.clone())).unwrap());
        }

        pretty_assertions_sorted::assert_eq!(outputs, expected);
        Ok(())
    }

    pub(crate) async fn setup_multi_tx_trace_pending_test(
    ) -> anyhow::Result<(RpcContext, Vec<Trace>)> {
        use super::super::simulate_transactions::tests::fixtures;

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
                transaction_hash: transaction_hash!("0x1"),
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
                l1_da_mode: starknet_gateway_types::reply::L1DataAvailabilityMode::Blob,
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

        pretty_assertions_sorted::assert_eq!(
            output
                .serialize(Serializer {
                    version: RpcVersion::V06,
                })
                .unwrap(),
            serde_json::to_value(expected).unwrap()
        );
        Ok(())
    }
}
