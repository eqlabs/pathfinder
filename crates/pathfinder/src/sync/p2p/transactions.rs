use anyhow::Context;
use pathfinder_common::{transaction::Transaction, BlockHeader};
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

pub(super) async fn persist(
    storage: Storage,
    block: BlockHeader,
    transactions: Vec<Transaction>,
) -> anyhow::Result<()> {
    spawn_blocking(move || {
        let mut db = storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;
        db.insert_transaction_data(
            block.hash,
            block.number,
            &transactions
                .into_iter()
                .map(|tx| pathfinder_storage::TransactionData {
                    transaction: tx,
                    receipt: None,
                    events: None,
                })
                .collect::<Vec<_>>(),
        )
        .context("Inserting transactions")?;
        db.commit().context("Committing database transaction")
    })
    .await
    .context("Joining blocking task")??;
    Ok(())
}
