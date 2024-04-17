use std::num::NonZeroUsize;

use anyhow::Context;
use p2p::client::peer_agnostic::TransactionsForBlock;
use p2p::PeerData;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockHeader, BlockNumber};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

use super::error::SyncError;

pub(super) async fn next_missing(
    storage: Storage,
    head: BlockNumber,
) -> anyhow::Result<Option<BlockNumber>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        let first_block = db
            .first_block_without_transactions()
            .context("Querying first block without transactions")?;

        match first_block {
            Some(first_block) if first_block <= head => Ok(Some(first_block)),
            Some(_) | None => Ok(None),
        }
    })
    .await
    .context("Joining blocking task")?
}

pub(super) fn counts_stream(
    storage: Storage,
    mut start: BlockNumber,
    stop_inclusive: BlockNumber,
) -> impl futures::Stream<Item = anyhow::Result<usize>> {
    const BATCH_SIZE: usize = 1000;

    async_stream::try_stream! {
        let mut batch = Vec::new();

        while start <= stop_inclusive {
            if let Some(counts) = batch.pop() {
                yield counts;
                continue;
            }

            let batch_size = NonZeroUsize::new(
                BATCH_SIZE.min(
                    (stop_inclusive.get() - start.get() + 1)
                        .try_into()
                        .expect("ptr size is 64bits"),
                ),
            )
            .expect(">0");
            let storage = storage.clone();

            batch = tokio::task::spawn_blocking(move || {
                let mut db = storage
                    .connection()
                    .context("Creating database connection")?;
                let db = db.transaction().context("Creating database transaction")?;
                db.transaction_counts(start.into(), batch_size)
                    .context("Querying transaction counts")
            })
            .await
            .context("Joining blocking task")??;

            if batch.is_empty() {
                Err(anyhow::anyhow!(
                    "No transaction counts found for range: start {start}, batch_size: {batch_size}"
                ))?;
                break;
            }

            start += batch.len().try_into().expect("ptr size is 64bits");
        }
    }
}

pub(super) async fn verify_commitment(
    transactions: PeerData<TransactionsForBlock>,
    storage: Storage,
) -> Result<PeerData<TransactionsForBlock>, SyncError> {
    let PeerData {
        peer,
        data: transactions,
    } = transactions;

    todo!()
}

pub(super) async fn persist(
    storage: Storage,
    transactions: Vec<PeerData<TransactionsForBlock>>,
) -> Result<BlockNumber, SyncError> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        let tail = transactions
            .last()
            .map(|x| x.data.0)
            .context("Verification results are empty, no block to persist")?;

        for (block_number, transactions) in transactions.into_iter().map(|x| x.data) {
            db.insert_transaction_data(block_number, &transactions, None)
                .context("Inserting transactions")?;
        }

        db.commit().context("Committing database transaction");
        Ok(tail)
    })
    .await
    .context("Joining blocking task")?
}
