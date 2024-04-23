use anyhow::Context;
use pathfinder_common::{BlockId, TransactionHash};

use crate::context::RpcContext;
use crate::v02::types::reply::BlockStatus;
use crate::v07::dto;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    block_id: BlockId,
}

#[derive(serde::Serialize)]
#[serde(untagged)]
pub enum Output {
    Full(BlockWithTxHashes),
    Pending(PendingBlockWithTxHashes),
}

#[derive(serde::Serialize)]
pub struct BlockWithTxHashes {
    #[serde(flatten)]
    header: dto::header::Header,
    status: BlockStatus,
    transactions: Vec<TransactionHash>,
}

#[derive(serde::Serialize)]
pub struct PendingBlockWithTxHashes {
    #[serde(flatten)]
    header: dto::header::PendingHeader,
    status: BlockStatus,
    transactions: Vec<TransactionHash>,
}

crate::error::generate_rpc_error_subset!(Error: BlockNotFound);

/// Get block information with transaction hashes given the block id
pub async fn get_block_with_tx_hashes(context: RpcContext, input: Input) -> Result<Output, Error> {
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

                let transactions = pending.block.transactions.iter().map(|t| t.hash).collect();

                return Ok(Output::Pending(PendingBlockWithTxHashes {
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
            .transaction_hashes_for_block(header.number.into())
            .context("Reading transaction hashes")?
            .context("Transaction hashes missing")?;

        Ok(Output::Full(BlockWithTxHashes {
            header: header.into(),
            status,
            transactions,
        }))
    })
    .await
    .context("Joining blocking task")?
}
