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

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use crate::storage::schema;

    use super::*;

    #[test]
    fn columns_are_dropped() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();

        // Manually add the columns in.
        transaction
            .execute("ALTER TABLE starknet_blocks ADD COLUMN transactions", [])
            .context("Adding transactions from starknet_blocks table")
            .unwrap();
        transaction
            .execute(
                "ALTER TABLE starknet_blocks ADD COLUMN transaction_receipts",
                [],
            )
            .context("Adding transaction receipts from starknet_blocks table")
            .unwrap();

        migrate(&transaction).unwrap();

        // Collect all the column names in table `starknet_blocks`.
        let mut columns = Vec::new();
        let mut stmt = transaction
            .prepare("select name from pragma_table_info('starknet_blocks')")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();
        while let Some(row) = rows.next().unwrap() {
            columns.push(row.get_ref_unwrap("name").as_str().unwrap().to_owned());
        }

        // The dropped columns should be gone.
        assert!(!columns.contains(&"transactions".to_string()));
        assert!(!columns.contains(&"transaction_receipts".to_string()));
    }

    #[test]
    fn succeeds_if_columns_are_already_dropped() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();

        migrate(&transaction).unwrap();
    }
}
