use anyhow::Context;
use rusqlite::{params, Transaction};
use tracing::info;

use crate::storage::schema::PostMigrationAction;

/// This schema migration adds ZTSD compression to the Starknet transaction and transaction receipts.
/// There are no physical changes to the actual schema, but simply the data in these two columns.
pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    let todo: u32 = transaction
        .query_row("SELECT count(1) FROM starknet_blocks", [], |r| r.get(0))
        .unwrap();
    if todo == 0 {
        return Ok(PostMigrationAction::None);
    }

    info!("Compressing {} rows of transaction data", todo);

    let mut stmt = transaction
        .prepare("SELECT number, transactions, transaction_receipts FROM starknet_blocks")?;
    let mut rows = stmt.query([])?;

    let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

    while let Some(r) = rows.next()? {
        let number = r.get_ref_unwrap("number").as_i64()?;
        let transactions = r.get_ref_unwrap("transactions").as_blob()?;
        let transaction_receipts = r.get_ref_unwrap("transaction_receipts").as_blob()?;

        let transactions = compressor
            .compress(transactions)
            .context("Compress transactions")?;
        let transaction_receipts = compressor
            .compress(transaction_receipts)
            .context("Compress transaction receipts")?;

        let diff_count = transaction.execute("UPDATE starknet_blocks SET transactions = ?1, transaction_receipts = ?2 WHERE number = ?3",
            params![&transactions, &transaction_receipts, number]).context("Update transaction data")?;
        assert_eq!(diff_count, 1);
    }

    // Database should be vacuum'd to take advantage of the compression savings.
    Ok(PostMigrationAction::Vacuum)
}
