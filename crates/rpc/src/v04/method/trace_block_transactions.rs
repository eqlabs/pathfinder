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
    transaction_hash: TransactionHash,
    trace_root: TransactionTrace,
}

#[derive(Debug, Serialize, Eq, PartialEq)]
pub struct TraceBlockTransactionsOutput(Vec<Trace>);

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
        let mut db = context.storage.connection()?;
        tokio::task::spawn_blocking(move || {
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
        .await??
    };

    let block_id = pathfinder_common::BlockId::Hash(input.block_hash);
    let execution_state = crate::executor::execution_state(context, block_id, gas_price).await?;

    let traces = tokio::task::spawn_blocking(move || {
        pathfinder_executor::trace_all(execution_state, transactions)
    })
    .await??;

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

    use super::*;

    use pathfinder_common::{
        class_hash, BlockHeader, BlockNumber, BlockTimestamp, CallParam, ContractAddress,
        EntryPoint, GasPrice,
    };
    use pathfinder_storage::Storage;
    use starknet_gateway_types::reply as gateway;

    pub(crate) fn setup_trace_test() -> anyhow::Result<(Storage, gateway::Block, TransactionTrace)>
    {
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
        const TEST_CLASS: &[u8] = include_bytes!("../../../fixtures/trace/class.json");
        tx.insert_cairo_class_at(class_hash, TEST_CLASS, block.block_number)?;

        let transaction_data = block
            .transactions
            .iter()
            .cloned()
            .zip(block.transaction_receipts.iter().cloned())
            .collect::<Vec<_>>();
        tx.insert_transaction_data(block.block_hash, block.block_number, &transaction_data)?;
        tx.commit()?;

        use pathfinder_common::felt;
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

    #[tokio::test]
    async fn test_single_transaction() -> anyhow::Result<()> {
        let (storage, block, expected) = setup_trace_test()?;
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
}
