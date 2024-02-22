use anyhow::Context;
use pathfinder_common::{BlockNumber, TransactionIndex};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

pub async fn missing_transactions(
    storage: Storage,
    before_block: Option<BlockNumber>,
) -> anyhow::Result<Vec<(BlockNumber, Vec<TransactionIndex>)>> {
    spawn_blocking(move || {
        let mut result = Vec::new();
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        for (block_number, transaction_count) in
            db.blocks_with_missing_transactions(before_block, 10)?
        {
            let mut missing_transactions = Vec::new();
            let mut idx = 0;
            let transactions = db
                .transactions_for_block(block_number.into())?
                .ok_or_else(|| anyhow::anyhow!("Missing block {}", block_number))?
                .into_iter();
            for (tx, tx_idx) in transactions {
                while idx < tx_idx.get() {
                    missing_transactions.push(TransactionIndex::new_or_panic(idx));
                    idx += 1;
                }
                idx += 1;
            }
            while idx < transaction_count {
                missing_transactions.push(TransactionIndex::new_or_panic(idx));
                idx += 1;
            }
            result.push((block_number, missing_transactions));
        }
        Ok(result)
    })
    .await
    .context("Joining blocking task")?
}
