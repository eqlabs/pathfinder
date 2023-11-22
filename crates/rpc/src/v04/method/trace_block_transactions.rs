use anyhow::Context;
use pathfinder_common::{BlockHash, TransactionHash};
use pathfinder_executor::{CallError, ExecutionState};
use serde::{Deserialize, Serialize};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply::transaction::Transaction as GatewayTransaction;

use crate::executor::VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY;
use crate::v04::v04_method::simulate_transactions::dto::map_gateway_trace;
use crate::{compose_executor_transaction, context::RpcContext, executor::ExecutionStateError};

use super::simulate_transactions::dto::TransactionTrace;

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct TraceBlockTransactionsInput {
    block_hash: BlockHash,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct Trace {
    pub transaction_hash: TransactionHash,
    pub trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceBlockTransactionsOutput(pub Vec<Trace>);

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
            CallError::ContractNotFound => Self::Custom(anyhow::anyhow!("Contract not found")),
            CallError::InvalidMessageSelector => {
                Self::Custom(anyhow::anyhow!("Invalid message selector"))
            }
            CallError::Reverted(reason) => Self::Custom(anyhow::anyhow!("Reverted: {reason}")),
            CallError::Internal(e) => Self::Internal(e),
            CallError::Custom(e) => Self::Custom(e),
        }
    }
}

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    enum LocalExecution {
        Success(Vec<Trace>),
        Unsupported(Vec<GatewayTransaction>),
    }

    let span = tracing::Span::current();

    let storage = context.storage.clone();
    let traces = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let db = db.transaction()?;

        let header = db
            .block_header(input.block_hash.into())?
            .ok_or(TraceBlockTransactionsError::InvalidBlockHash)?;

        let transactions = db
            .transactions_for_block(input.block_hash.into())?
            .ok_or(TraceBlockTransactionsError::InvalidBlockHash)?;

        let starknet_version = header
            .starknet_version
            .parse_as_semver()
            .context("Parsing starknet version")?
            .unwrap_or(semver::Version::new(0, 0, 0));
        if starknet_version
            < VERSIONS_LOWER_THAN_THIS_SHOULD_FALL_BACK_TO_FETCHING_TRACE_FROM_GATEWAY
        {
            return Ok::<_, TraceBlockTransactionsError>(LocalExecution::Unsupported(transactions));
        }

        let transactions = transactions
            .iter()
            .map(|transaction| compose_executor_transaction(transaction, &db))
            .collect::<Result<Vec<_>, _>>()?;

        let state = ExecutionState::trace(&db, context.chain_id, header, None);
        let traces = pathfinder_executor::trace_all(state, transactions, true, true)?;

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
        .block_traces(input.block_hash.into())
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
                        let transaction_hash = tx.hash();
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
    use pathfinder_common::{
        felt, BlockHeader, ChainId, GasPrice, SierraHash, TransactionIndex, TransactionNonce,
    };
    use starknet_gateway_types::reply::{
        self as gateway,
        transaction::{EntryPointType, ExecutionStatus, Receipt},
    };

    use crate::v02::types::request::BroadcastedDeployAccountTransaction;

    use super::*;

    impl From<crate::v02::types::request::BroadcastedTransaction>
        for starknet_gateway_types::reply::transaction::Transaction
    {
        fn from(value: crate::v02::types::request::BroadcastedTransaction) -> Self {
            match value {
                crate::v02::types::request::BroadcastedTransaction::Declare(
                    crate::v02::types::request::BroadcastedDeclareTransaction::V0(declare),
                ) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    let transaction_hash = declare.transaction_hash(ChainId::TESTNET, class_hash);
                    starknet_gateway_types::reply::transaction::Transaction::Declare(
                        gateway::transaction::DeclareTransaction::V0(
                            gateway::transaction::DeclareTransactionV0V1 {
                                class_hash,
                                max_fee: declare.max_fee,
                                nonce: TransactionNonce::default(),
                                sender_address: declare.sender_address,
                                signature: declare.signature,
                                transaction_hash,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Declare(
                    crate::v02::types::request::BroadcastedDeclareTransaction::V1(declare),
                ) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    let transaction_hash = declare.transaction_hash(ChainId::TESTNET, class_hash);
                    starknet_gateway_types::reply::transaction::Transaction::Declare(
                        gateway::transaction::DeclareTransaction::V1(
                            gateway::transaction::DeclareTransactionV0V1 {
                                class_hash,
                                max_fee: declare.max_fee,
                                nonce: TransactionNonce::default(),
                                sender_address: declare.sender_address,
                                signature: declare.signature,
                                transaction_hash,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Declare(
                    crate::v02::types::request::BroadcastedDeclareTransaction::V2(declare),
                ) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    let transaction_hash = declare.transaction_hash(ChainId::TESTNET, class_hash);
                    starknet_gateway_types::reply::transaction::Transaction::Declare(
                        gateway::transaction::DeclareTransaction::V2(
                            gateway::transaction::DeclareTransactionV2 {
                                class_hash,
                                max_fee: declare.max_fee,
                                nonce: TransactionNonce::default(),
                                sender_address: declare.sender_address,
                                signature: declare.signature,
                                transaction_hash,
                                compiled_class_hash: declare.compiled_class_hash,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Declare(
                    crate::v02::types::request::BroadcastedDeclareTransaction::V3(declare),
                ) => {
                    let class_hash = declare.contract_class.class_hash().unwrap().hash();
                    let transaction_hash = declare.transaction_hash(ChainId::TESTNET, class_hash);
                    starknet_gateway_types::reply::transaction::Transaction::Declare(
                        gateway::transaction::DeclareTransaction::V3(
                            gateway::transaction::DeclareTransactionV3 {
                                class_hash,
                                nonce: TransactionNonce::default(),
                                sender_address: declare.sender_address,
                                signature: declare.signature,
                                transaction_hash,
                                compiled_class_hash: declare.compiled_class_hash,
                                nonce_data_availability_mode: declare
                                    .nonce_data_availability_mode
                                    .into(),
                                fee_data_availability_mode: declare
                                    .fee_data_availability_mode
                                    .into(),
                                resource_bounds: declare.resource_bounds.into(),
                                tip: declare.tip,
                                paymaster_data: declare.paymaster_data,
                                account_deployment_data: declare.account_deployment_data,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::DeployAccount(
                    BroadcastedDeployAccountTransaction::V0V1(deploy),
                ) => starknet_gateway_types::reply::transaction::Transaction::DeployAccount(
                    gateway::transaction::DeployAccountTransaction::V0V1(
                        gateway::transaction::DeployAccountTransactionV0V1 {
                            contract_address: deploy.deployed_contract_address(),
                            transaction_hash: deploy.transaction_hash(ChainId::TESTNET),
                            max_fee: deploy.max_fee,
                            version: deploy.version,
                            signature: deploy.signature,
                            nonce: deploy.nonce,
                            contract_address_salt: deploy.contract_address_salt,
                            constructor_calldata: deploy.constructor_calldata,
                            class_hash: deploy.class_hash,
                        },
                    ),
                ),
                crate::v02::types::request::BroadcastedTransaction::DeployAccount(
                    BroadcastedDeployAccountTransaction::V3(deploy),
                ) => {
                    let transaction_hash = deploy.transaction_hash(ChainId::TESTNET);

                    starknet_gateway_types::reply::transaction::Transaction::DeployAccount(
                        gateway::transaction::DeployAccountTransaction::V3(
                            gateway::transaction::DeployAccountTransactionV3 {
                                version: deploy.version,
                                class_hash: deploy.class_hash,
                                nonce: deploy.nonce,
                                sender_address: deploy.deployed_contract_address(),
                                contract_address_salt: deploy.contract_address_salt,
                                constructor_calldata: deploy.constructor_calldata,
                                signature: deploy.signature,
                                transaction_hash,
                                nonce_data_availability_mode: deploy
                                    .nonce_data_availability_mode
                                    .into(),
                                fee_data_availability_mode: deploy
                                    .fee_data_availability_mode
                                    .into(),
                                resource_bounds: deploy.resource_bounds.into(),
                                tip: deploy.tip,
                                paymaster_data: deploy.paymaster_data,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Invoke(
                    crate::v02::types::request::BroadcastedInvokeTransaction::V0(invoke),
                ) => {
                    let transaction_hash = invoke.transaction_hash(ChainId::TESTNET);
                    starknet_gateway_types::reply::transaction::Transaction::Invoke(
                        gateway::transaction::InvokeTransaction::V0(
                            gateway::transaction::InvokeTransactionV0 {
                                calldata: invoke.calldata,
                                sender_address: invoke.contract_address,
                                entry_point_type: Some(EntryPointType::External),
                                entry_point_selector: invoke.entry_point_selector,
                                max_fee: invoke.max_fee,
                                signature: invoke.signature,
                                transaction_hash,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Invoke(
                    crate::v02::types::request::BroadcastedInvokeTransaction::V1(invoke),
                ) => {
                    let transaction_hash = invoke.transaction_hash(ChainId::TESTNET);
                    starknet_gateway_types::reply::transaction::Transaction::Invoke(
                        gateway::transaction::InvokeTransaction::V1(
                            gateway::transaction::InvokeTransactionV1 {
                                calldata: invoke.calldata,
                                sender_address: invoke.sender_address,
                                max_fee: invoke.max_fee,
                                signature: invoke.signature,
                                nonce: invoke.nonce,
                                transaction_hash,
                            },
                        ),
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Invoke(
                    crate::v02::types::request::BroadcastedInvokeTransaction::V3(invoke),
                ) => {
                    let transaction_hash = invoke.transaction_hash(ChainId::TESTNET);
                    starknet_gateway_types::reply::transaction::Transaction::Invoke(
                        gateway::transaction::InvokeTransaction::V3(
                            gateway::transaction::InvokeTransactionV3 {
                                nonce: TransactionNonce::default(),
                                sender_address: invoke.sender_address,
                                signature: invoke.signature,
                                transaction_hash,
                                nonce_data_availability_mode: invoke
                                    .nonce_data_availability_mode
                                    .into(),
                                fee_data_availability_mode: invoke
                                    .fee_data_availability_mode
                                    .into(),
                                resource_bounds: invoke.resource_bounds.into(),
                                tip: invoke.tip,
                                paymaster_data: invoke.paymaster_data,
                                calldata: invoke.calldata,
                                account_deployment_data: invoke.account_deployment_data,
                            },
                        ),
                    )
                }
            }
        }
    }

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
            fixtures::input::declare(account_contract_address),
            fixtures::input::universal_deployer(
                account_contract_address,
                universal_deployer_address,
            ),
            fixtures::input::invoke(account_contract_address),
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
                "compiler version",
            )?;

            let next_block_header = BlockHeader::builder()
                .with_number(last_block_header.number + 1)
                .with_eth_l1_gas_price(GasPrice(1))
                .with_parent_hash(last_block_header.hash)
                .with_starknet_version(last_block_header.starknet_version)
                .with_sequencer_address(last_block_header.sequencer_address)
                .with_timestamp(last_block_header.timestamp)
                .finalize_with_hash(BlockHash(felt!("0x1")));
            tx.insert_block_header(&next_block_header)?;

            let dummy_receipt: Receipt = Receipt {
                actual_fee: None,
                events: vec![],
                execution_resources: None,
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: vec![],
                transaction_hash: TransactionHash(felt!("0x1")),
                transaction_index: TransactionIndex::new_or_panic(0),
                execution_status: ExecutionStatus::default(),
                revert_error: None,
            };
            tx.insert_transaction_data(
                next_block_header.hash,
                next_block_header.number,
                &[
                    (transactions[0].clone().into(), dummy_receipt.clone()),
                    (transactions[1].clone().into(), dummy_receipt.clone()),
                    (transactions[2].clone().into(), dummy_receipt.clone()),
                ],
            )?;
            tx.commit()?;

            next_block_header
        };

        let traces = vec![
            Trace {
                transaction_hash: transactions[0]
                    .transaction_hash(ChainId::TESTNET, Some(fixtures::SIERRA_HASH)),
                trace_root: traces[0].clone(),
            },
            Trace {
                transaction_hash: transactions[1].transaction_hash(ChainId::TESTNET, None),
                trace_root: traces[1].clone(),
            },
            Trace {
                transaction_hash: transactions[2].transaction_hash(ChainId::TESTNET, None),
                trace_root: traces[2].clone(),
            },
        ];

        Ok((context, next_block_header, traces))
    }

    #[tokio::test]
    async fn test_multiple_transactions() -> anyhow::Result<()> {
        let (context, next_block_header, traces) = setup_multi_tx_trace_test().await?;

        let input = TraceBlockTransactionsInput {
            block_hash: next_block_header.hash,
        };
        let output = trace_block_transactions(context, input).await.unwrap();
        let expected = TraceBlockTransactionsOutput(traces);

        pretty_assertions::assert_eq!(output, expected);
        Ok(())
    }
}
