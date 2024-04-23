use anyhow::Context;
use pathfinder_common::BlockId;
use serde::Serialize;

use crate::context::RpcContext;
use crate::v02::types::reply::BlockStatus;
use crate::v06::types::TransactionWithHash;
use crate::v07::dto;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    block_id: BlockId,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Output {
    Full(BlockWithTxs),
    Pending(PendingBlockWithTxs),
}

#[derive(Serialize)]
pub struct BlockWithTxs {
    #[serde(flatten)]
    header: dto::header::Header,
    status: BlockStatus,
    transactions: Vec<TransactionWithHash>,
}

#[derive(Serialize)]
pub struct PendingBlockWithTxs {
    #[serde(flatten)]
    header: dto::header::PendingHeader,
    status: BlockStatus,
    transactions: Vec<TransactionWithHash>,
}

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

/// Get block information with full transactions given the block id
pub async fn get_block_with_txs(context: RpcContext, input: Input) -> Result<Output, Error> {
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = context
            .storage
            .connection()
            .context("Opening database connection")?;

        let transaction = connection
            .transaction()
            .context("Creating database transaction")?;

        let block_id = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&transaction)
                    .context("Querying pending data")?;

                let transactions = pending
                    .block
                    .transactions
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect();

                return Ok(Output::Pending(PendingBlockWithTxs {
                    header: pending.header().into(),
                    status: BlockStatus::Pending,
                    transactions,
                }));
            }
            other => other.try_into().expect("Only pending cast should fail"),
        };

        let header = transaction
            .block_header(block_id)
            .context("Reading block from database")?
            .ok_or(Error::BlockNotFound)?;

        let l1_accepted = transaction.block_is_l1_accepted(header.number.into())?;
        let status = if l1_accepted {
            BlockStatus::AcceptedOnL1
        } else {
            BlockStatus::AcceptedOnL2
        };

        let transactions = transaction
            .transactions_for_block(header.number.into())
            .context("Reading transactions from database")?
            .context("Transaction data missing")?
            .into_iter()
            .map(Into::into)
            .collect();

        Ok(Output::Full(BlockWithTxs {
            header: header.into(),
            status,
            transactions,
        }))
    })
    .await
    .context("Joining blocking task")?
}
