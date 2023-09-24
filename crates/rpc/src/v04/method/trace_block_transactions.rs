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
            CallError::ContractNotFound | CallError::InvalidMessageSelector => Self::Internal(
                anyhow::anyhow!("Failed to trace the transaction: {value:?}"),
            ),
            CallError::Reverted(e) => Self::Internal(anyhow::anyhow!("Transaction reverted: {e}")),
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
    let (transactions, gas_price): (Vec<_>, Option<U256>) = {
        let span = tracing::Span::current();

        let storage = context.storage.clone();
        tokio::task::spawn_blocking(move || {
            let _g = span.enter();

            let mut db = storage.connection()?;
            let tx = db.transaction()?;

            let gas_price: Option<U256> = tx
                .block_header(pathfinder_storage::BlockId::Hash(input.block_hash))?
                .map(|header| U256::from(header.gas_price.0));

            let (transactions, _): (Vec<_>, Vec<_>) = tx
                .transaction_data_for_block(BlockId::Hash(input.block_hash))?
                .ok_or(TraceBlockTransactionsError::InvalidBlockHash)?
                .into_iter()
                .unzip();

            let transactions = transactions
                .into_iter()
                .map(|transaction| compose_executor_transaction(transaction, &tx))
                .collect::<anyhow::Result<Vec<_>, _>>()?;

            Ok::<_, TraceBlockTransactionsError>((transactions, gas_price))
        })
        .await
        .context("trace_block_transactions: fetch block & transactions")??
    };

    let block_id = pathfinder_common::BlockId::Hash(input.block_hash);
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
    use crate::{
        v02::method::call::FunctionCall,
        v04::method::simulate_transactions::dto::{
            CallType, DeployAccountTxnTrace, EntryPointType, FunctionInvocation,
        },
    };

    use pathfinder_common::{
        class_hash, felt, BlockHeader, BlockNumber, BlockTimestamp, CallParam, ChainId,
        ContractAddress, EntryPoint, GasPrice, SierraHash, TransactionIndex, TransactionNonce,
    };
    use pathfinder_storage::Storage;
    use starknet_gateway_types::reply::{
        self as gateway,
        transaction::{ExecutionStatus, Receipt},
    };

    use super::*;

    pub(crate) fn setup_single_tx_trace_test(
    ) -> anyhow::Result<(Storage, gateway::Block, TransactionTrace)> {
        const TEST_BLOCK: &str = include_str!("../../../fixtures/trace/block.json");
        let block: gateway::Block = serde_json::from_str(TEST_BLOCK)?;

        let storage = Storage::in_memory()?;
        let mut db = storage.connection()?;
        let tx = db.transaction()?;

        let parent = BlockHeader::builder()
            .with_number(BlockNumber::GENESIS)
            .finalize_with_hash(block.parent_block_hash);
        tx.insert_block_header(&parent)?;

        let header = BlockHeader::builder()
            .with_number(block.block_number)
            .with_timestamp(BlockTimestamp::new_or_panic(0))
            .with_gas_price(block.gas_price.unwrap_or(GasPrice(1)))
            .finalize_with_hash(block.block_hash);
        tx.insert_block_header(&header)?;

        let class_hash =
            class_hash!("0x6f3ec04229f8f9663ee7d5bb9d2e06f213ba8c20eb34c58c25a54ef8fc591cb");
        let test_class = ungzip(include_bytes!("../../../fixtures/trace/class.json.gzip"));
        tx.insert_cairo_class_at(class_hash, &test_class, block.block_number)?;

        let transaction_data = block
            .transactions
            .iter()
            .cloned()
            .zip(block.transaction_receipts.iter().cloned())
            .collect::<Vec<_>>();
        tx.insert_transaction_data(block.block_hash, block.block_number, &transaction_data)?;
        tx.commit()?;

        let expected = TransactionTrace::DeployAccount(DeployAccountTxnTrace {
            constructor_invocation: Some(FunctionInvocation {
                call_type: CallType::Call,
                caller_address: felt!("0x0"),
                class_hash: Some(felt!(
                    "0x06F3EC04229F8F9663EE7D5BB9D2E06F213BA8C20EB34C58C25A54EF8FC591CB"
                )),
                calls: vec![],
                entry_point_type: EntryPointType::Constructor,
                events: vec![],
                function_call: FunctionCall {
                    contract_address: ContractAddress(felt!(
                        "0x0325BF20D89B86FAFA54BE01C3571D3B1BD5562E7BA13E9021E2F4BE86C605A1"
                    )),
                    entry_point_selector: EntryPoint(felt!(
                        "0x028FFE4FF0F226A9107253E17A904099AA4F63A02A5621DE0576E5AA71BC5194"
                    )),
                    calldata: vec![CallParam(felt!(
                        "0x06D1B9433B879895E4D0CE6058C0C4AC66324BB0B18F9A6F7823EDC110463169"
                    ))],
                },
                messages: vec![],
                result: vec![],
            }),
            fee_transfer_invocation: None,
            validate_invocation: None,
        });
        Ok((storage, block, expected))
    }

    fn ungzip(src: &[u8]) -> Vec<u8> {
        use flate2::bufread::GzDecoder;
        use std::io::Read;
        let mut decoder = GzDecoder::new(src);
        let mut target = Vec::new();
        decoder.read_to_end(&mut target).unwrap();
        target
    }

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
                                class_hash: class_hash.clone(),
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
                                class_hash: class_hash.clone(),
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
                                class_hash: class_hash.clone(),
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

        {
            let mut db = storage.connection()?;
            let tx = db.transaction()?;
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
                last_block_header.hash,
                last_block_header.number,
                &[
                    (transactions[0].clone().into(), dummy_receipt.clone()),
                    (transactions[1].clone().into(), dummy_receipt.clone()),
                    (transactions[2].clone().into(), dummy_receipt.clone()),
                ],
            )?;
            tx.insert_sierra_class(
                &SierraHash(fixtures::SIERRA_HASH.0),
                fixtures::SIERRA_DEFINITION,
                &fixtures::CASM_HASH,
                fixtures::CASM_DEFINITION,
                "compiler version",
            )?;
            tx.commit()?;
        }

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

        Ok((context, last_block_header, traces))
    }

    #[ignore = "TODO FIXME: insufficient balance for tx"]
    #[tokio::test]
    async fn test_single_transaction() -> anyhow::Result<()> {
        let (storage, block, expected) = setup_single_tx_trace_test()?;
        let context = RpcContext::for_tests().with_storage(storage);

        let input = TraceBlockTransactionsInput {
            block_hash: block.block_hash,
        };
        let output = trace_block_transactions(context, input).await.unwrap();

        let expected = TraceBlockTransactionsOutput(vec![Trace {
            transaction_hash: block.transactions[0].hash(),
            trace_root: expected,
        }]);

        pretty_assertions::assert_eq!(output, expected);
        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_transactions() -> anyhow::Result<()> {
        let (context, last_block_header, traces) = setup_multi_tx_trace_test().await?;

        let input = TraceBlockTransactionsInput {
            block_hash: last_block_header.hash,
        };
        let output = trace_block_transactions(context, input).await.unwrap();
        let expected = TraceBlockTransactionsOutput(traces);

        pretty_assertions::assert_eq!(output, expected);
        Ok(())
    }
}
