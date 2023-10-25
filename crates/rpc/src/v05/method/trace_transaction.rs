use anyhow::Context;
use pathfinder_common::{BlockHash, BlockId, GasPrice, StarknetVersion, TransactionHash};
use pathfinder_executor::CallError;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use starknet_gateway_client::GatewayApi;

use crate::compose_executor_transaction;
use crate::v05::method::trace_block_transactions::map_gateway_trace;
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
    InvalidTxnHash,
    NoTraceAvailable(TraceError),
    ContractErrorV05 { revert_error: String },
}

impl From<ExecutionStateError> for TraceTransactionError {
    fn from(value: ExecutionStateError) -> Self {
        match value {
            ExecutionStateError::BlockNotFound => {
                Self::Internal(anyhow::anyhow!("Block not found"))
            }
            ExecutionStateError::Internal(e) => Self::Internal(e),
        }
    }
}

impl From<CallError> for TraceTransactionError {
    fn from(value: CallError) -> Self {
        match value {
            CallError::ContractNotFound => Self::Internal(anyhow::anyhow!("Contract not found")),
            CallError::InvalidMessageSelector => {
                Self::Internal(anyhow::anyhow!("Invalid message selector"))
            }
            CallError::Reverted(revert_error) => Self::ContractErrorV05 { revert_error },
            CallError::Internal(e) => Self::Internal(e),
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
            BlockNotFound => Self::Internal(anyhow::anyhow!("Block not found")),
            ContractErrorV05 { revert_error } => Self::ContractErrorV05 { revert_error },
        }
    }
}

impl From<TraceTransactionError> for ApplicationError {
    fn from(value: TraceTransactionError) -> Self {
        match value {
            TraceTransactionError::InvalidTxnHash => ApplicationError::InvalidTxnHash,
            TraceTransactionError::NoTraceAvailable(status) => {
                ApplicationError::NoTraceAvailable(status)
            }
            TraceTransactionError::ContractErrorV05 { revert_error } => {
                ApplicationError::ContractErrorV05 { revert_error }
            }
            TraceTransactionError::Internal(e) => ApplicationError::Internal(e),
        }
    }
}

pub async fn trace_transaction(
    context: RpcContext,
    input: TraceTransactionInput,
) -> Result<TraceTransactionOutput, TraceTransactionError> {
    let (transactions, gas_price, parent_block_hash, starknet_version) =
        fetch_block_transactions(context.clone(), input.transaction_hash).await?;

    const V_0_12_0: semver::Version = semver::Version::new(0, 12, 0);
    let starknet_version = starknet_version
        .parse_as_semver()
        .context("Parsing starknet version")?
        .unwrap_or(semver::Version::new(0, 0, 0));
    if starknet_version <= V_0_12_0 {
        let trace = context
            .sequencer
            .transaction_trace(input.transaction_hash)
            .await
            .context("Proxying call to feeder gateway")?;

        let transaction = transactions
            .into_iter()
            .find(|tx| input.transaction_hash == pathfinder_executor::transaction_hash(tx))
            .context("Transaction hash was not found")?;

        let trace = map_gateway_trace(transaction, trace);

        return Ok(TraceTransactionOutput(trace));
    }

    let parent_block_id = BlockId::Hash(parent_block_hash);
    let gas_price = Some(U256::from(gas_price.0));
    let execution_state =
        crate::executor::execution_state(context, parent_block_id, gas_price).await?;

    let span = tracing::Span::current();
    let trace = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        pathfinder_executor::trace_one(
            execution_state,
            transactions,
            input.transaction_hash,
            true,
            true,
        )
    })
    .await
    .context("trace_transaction: execution")??;

    Ok(TraceTransactionOutput(trace.into()))
}

async fn fetch_block_transactions(
    context: RpcContext,
    transaction_hash: TransactionHash,
) -> Result<
    (
        Vec<pathfinder_executor::Transaction>,
        GasPrice,
        BlockHash,
        StarknetVersion,
    ),
    TraceTransactionError,
> {
    let span = tracing::Span::current();
    let storage = context.storage.clone();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction()?;

        let pending_data = context
            .pending_data
            .get(&tx)
            .context("Querying pending data")?;
        let pending_block = &pending_data.block;

        if pending_block
            .transactions
            .iter()
            .any(|tx| tx.hash() == transaction_hash)
        {
            let transactions = pending_block
                .transactions
                .iter()
                .map(|transaction| compose_executor_transaction(transaction.clone(), &tx))
                .collect::<Result<Vec<_>, _>>()?;

            return Ok((
                transactions,
                pending_block.gas_price,
                pending_block.parent_hash,
                pending_block.starknet_version.clone(),
            ));
        }

        let block_hash = tx
            .transaction_block_hash(transaction_hash)?
            .ok_or(TraceTransactionError::InvalidTxnHash)?;

        super::trace_block_transactions::fetch_block_transactions(&tx, block_hash.into())
            .map_err(Into::into)
    })
    .await
    .context("trace_transaction: fetch & map the transaction")?
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
            pretty_assertions::assert_eq!(output, expected);
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
            pretty_assertions::assert_eq!(output, expected);
        }

        Ok(())
    }
}
