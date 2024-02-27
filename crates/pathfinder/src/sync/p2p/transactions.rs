use anyhow::Context;
use futures::{stream, Stream, StreamExt};
use pathfinder_common::{transaction::Transaction, BlockHeader, BlockNumber};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

pub fn blocks_without_transactions(
    storage: Storage,
) -> impl Stream<Item = anyhow::Result<BlockHeader>> {
    stream::unfold(
        (BlockNumber::new_or_panic(0), storage),
        move |(block_number, storage)| async move {
            let result = spawn_blocking({
                let storage = storage.clone();
                move || {
                    let mut db = storage
                        .connection()
                        .context("Creating database connection")?;
                    let db = db.transaction().context("Creating database transaction")?;
                    let blocks = db.blocks_without_transactions(block_number, 100)?;
                    if blocks.is_empty() {
                        Ok(None)
                    } else {
                        let next_block = blocks.last().unwrap().number + 1;
                        Ok(Some((blocks, (next_block, storage))))
                    }
                }
            })
            .await
            .context("Joining blocking task");
            match result {
                Ok(Ok(None)) => None,
                Ok(Ok(Some((blocks, state)))) => Some((Ok(blocks), state)),
                Ok(Err(err)) => Some((Err(err), (block_number, storage))),
                Err(err) => Some((Err(err), (block_number, storage))),
            }
        },
    )
    .flat_map(|result| match result {
        Ok(blocks) => stream::iter(blocks.into_iter().map(Ok)).boxed(),
        Err(err) => stream::once(async { Err(err) }).boxed(),
    })
}

pub async fn insert_transactions(
    storage: Storage,
    block: BlockHeader,
    transactions: Vec<Transaction>,
) -> anyhow::Result<()> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let transactions: Vec<_> = transactions
            .into_iter()
            .map(|tx| (tx, pathfinder_common::receipt::Receipt::default()))
            .collect();
        let db = db.transaction().context("Creating database transaction")?;
        db.insert_transaction_data(block.hash, block.number, &transactions)
    })
    .await
    .context("Joining blocking task")?
}
