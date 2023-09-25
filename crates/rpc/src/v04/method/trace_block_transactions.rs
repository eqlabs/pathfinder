use anyhow::Context;
use pathfinder_common::{BlockHash, TransactionHash};
use pathfinder_executor::CallError;
use pathfinder_storage::BlockId;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tokio::task::JoinError;

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
            CallError::ContractNotFound => Self::Internal(anyhow::anyhow!("Contract not found")),
            CallError::InvalidMessageSelector => Self::Internal(anyhow::anyhow!("Invalid message selector")),
            CallError::Reverted(reason) => Self::Internal(anyhow::anyhow!("Reverted: {reason}")),
            CallError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<JoinError> for TraceBlockTransactionsError {
    fn from(e: JoinError) -> Self {
        Self::Internal(anyhow::anyhow!("Join error: {e}"))
    }
}

pub async fn trace_block_transactions(
    context: RpcContext,
    input: TraceBlockTransactionsInput,
) -> Result<TraceBlockTransactionsOutput, TraceBlockTransactionsError> {
    let (transactions, gas_price, parent_block_hash): (Vec<_>, Option<U256>, BlockHash) = {
        let span = tracing::Span::current();

        let storage = context.storage.clone();
        tokio::task::spawn_blocking(move || {
            let _g = span.enter();

            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            let header = tx.block_header(pathfinder_storage::BlockId::Hash(input.block_hash))?;

            let parent_block_hash = header
                .as_ref()
                .map(|h| h.parent_hash)
                .ok_or(TraceBlockTransactionsError::InvalidBlockHash)?;

            let gas_price: Option<U256> =
                header.as_ref().map(|header| U256::from(header.gas_price.0));

            let (transactions, _): (Vec<_>, Vec<_>) = tx
                .transaction_data_for_block(BlockId::Hash(input.block_hash))?
                .ok_or(TraceBlockTransactionsError::InvalidBlockHash)?
                .into_iter()
                .unzip();

            let transactions = transactions
                .into_iter()
                .map(|transaction| compose_executor_transaction(transaction, &tx))
                .collect::<anyhow::Result<Vec<_>, _>>()?;

            Ok::<_, TraceBlockTransactionsError>((transactions, gas_price, parent_block_hash))
        })
        .await
        .context("trace_block_transactions: fetch block & transactions")??
    };

    let block_id = pathfinder_common::BlockId::Hash(parent_block_hash);
    let execution_state = crate::executor::execution_state(context, block_id, gas_price).await?;

    let span = tracing::Span::current();
    let traces = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        pathfinder_executor::trace_all(execution_state, transactions, true, true)
    })
    .await
    .context("trace_block_transactions: execution")??;

    let result = traces
        .into_iter()
        .map(|(hash, trace)| Trace {
            transaction_hash: hash,
            trace_root: trace.into(),
        })
        .collect();

    Ok(TraceBlockTransactionsOutput(result))
}

#[cfg(test)]
pub(crate) mod tests {
    use pathfinder_common::{
        felt, BlockHeader, ChainId, GasPrice, SierraHash, TransactionIndex, TransactionNonce,
    };
    use starknet_gateway_types::reply::{
        self as gateway,
        transaction::{ExecutionStatus, Receipt},
    };

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
                    let transaction_hash =
                        declare.transaction_hash(ChainId(felt!("0x1")), class_hash);
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
                    let transaction_hash =
                        declare.transaction_hash(ChainId(felt!("0x1")), class_hash);
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
                    let transaction_hash =
                        declare.transaction_hash(ChainId(felt!("0x1")), class_hash);
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
                crate::v02::types::request::BroadcastedTransaction::DeployAccount(deploy) => {
                    starknet_gateway_types::reply::transaction::Transaction::DeployAccount(
                        gateway::transaction::DeployAccountTransaction {
                            contract_address: deploy.deployed_contract_address(),
                            transaction_hash: deploy.transaction_hash(ChainId(felt!("0x1"))),
                            max_fee: deploy.max_fee,
                            version: deploy.version,
                            signature: deploy.signature,
                            nonce: deploy.nonce,
                            contract_address_salt: deploy.contract_address_salt,
                            constructor_calldata: deploy.constructor_calldata,
                            class_hash: deploy.class_hash,
                        },
                    )
                }
                crate::v02::types::request::BroadcastedTransaction::Invoke(
                    crate::v02::types::request::BroadcastedInvokeTransaction::V1(invoke),
                ) => {
                    let transaction_hash = invoke.transaction_hash(ChainId(felt!("0x1")));
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
                .with_gas_price(GasPrice(1))
                .with_parent_hash(last_block_header.hash)
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
                    .transaction_hash(ChainId(felt!("0x1")), Some(fixtures::SIERRA_HASH)),
                trace_root: traces[0].clone(),
            },
            Trace {
                transaction_hash: transactions[1].transaction_hash(ChainId(felt!("0x1")), None),
                trace_root: traces[1].clone(),
            },
            Trace {
                transaction_hash: transactions[2].transaction_hash(ChainId(felt!("0x1")), None),
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
