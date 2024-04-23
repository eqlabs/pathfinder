use anyhow::Context;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::BlockHeader;
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

pub(super) async fn persist(
    storage: Storage,
    block: BlockHeader,
    receipts: Vec<Receipt>,
) -> anyhow::Result<()> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        for (transaction_idx, receipt) in receipts.into_iter().enumerate() {
            db.update_receipt(block.number, transaction_idx, &receipt)
                .context("Updating receipt")?;
        }
        db.commit().context("Committing database transaction")
    })
    .await
    .context("Joining blocking task")??;
    Ok(())
}
