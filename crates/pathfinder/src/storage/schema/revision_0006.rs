use anyhow::Context;
use rusqlite::Transaction;

/// This schema migration fixes a mistake in the previous migration. It failed to
/// drop the transactions and transaction_receipts columns if the table was empty due to
/// to an early exit condition.
///
/// This mistake has since been rectified, but we should still fix databases that included
/// this bug.
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // Check if the columns still exist. Checking just one is enough as either both exist, or neither.
    //
    // This is necessary as sqlite will error when dropping a non-existant column.
    let count: usize = transaction
        .query_row(
            "SELECT COUNT(1) FROM pragma_table_info('starknet_blocks') where name='transactions'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    if count > 0 {
        // Remove transaction columns from blocks table.
        transaction
            .execute("ALTER TABLE starknet_blocks DROP COLUMN transactions", [])
            .context("Dropping transactions from starknet_blocks table")?;

        transaction
            .execute(
                "ALTER TABLE starknet_blocks DROP COLUMN transaction_receipts",
                [],
            )
            .context("Dropping transaction receipts from starknet_blocks table")?;
    }

    Ok(())
}
