use anyhow::Context;
use pathfinder_common::{transaction::Transaction, BlockHeader, BlockNumber};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

pub async fn blocks_without_transactions(
    storage: Storage,
    before_block: Option<BlockNumber>,
) -> anyhow::Result<Vec<BlockHeader>> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        db.blocks_without_transactions(before_block, 10)
    })
    .await
    .context("Joining blocking task")?
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
