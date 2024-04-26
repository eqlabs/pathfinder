use anyhow::Context;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::BlockHeader;
use pathfinder_storage::Storage;
use tokio::task::spawn_blocking;

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
        db.insert_transaction_data(
            block.number,
            &transactions
                .into_iter()
                .map(
                    |(transaction, receipt)| pathfinder_storage::TransactionData {
                        transaction,
                        receipt: Some(receipt),
                        events: None,
                    },
                )
                .collect::<Vec<_>>(),
        )
        .context("Inserting transactions with receipts")?;
        db.commit().context("Committing database transaction")
    })
    .await
    .context("Joining blocking task")??;
    Ok(())
}
