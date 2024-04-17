use std::num::NonZeroUsize;

use anyhow::Context;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{BlockHeader, BlockNumber};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

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

pub(super) async fn persist(
    storage: Storage,
    block: BlockHeader,
    transactions: Vec<(Transaction, Receipt)>,
) -> anyhow::Result<()> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        db.insert_transaction_data(block.number, &transactions, None)
            .context("Inserting transactions with receipts")?;
        db.commit().context("Committing database transaction")
    })
    .await
    .context("Joining blocking task")??;
    Ok(())
}
