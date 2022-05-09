use anyhow::Context;
use rusqlite::Transaction;

use crate::storage::schema::PostMigrationAction;

/// This schema migration fixes a mistake in the previous migration. It failed to
/// drop the transactions and transaction_receipts columns if the table was empty due to
/// to an early exit condition.
///
/// This mistake has since been rectified, but we should still fix databases that included
/// this bug.
pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    // Check if the columns still exist. Checking just one is enough as either both exist, or neither.
    //
    // This is necessary as sqlite will error when dropping a non-existant column. As a benefit
    // it also lets us skip vacuuming if nothing is done.
    let count: usize = transaction
        .query_row(
            "SELECT COUNT(1) FROM pragma_table_info('starknet_blocks') where name='transactions'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    if count == 0 {
        return Ok(PostMigrationAction::None);
    }

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

    // Database should be vacuum'd to defrag removal of transaction columns.
    Ok(PostMigrationAction::Vacuum)
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

        let action = migrate(&transaction).unwrap();
        assert_eq!(action, PostMigrationAction::Vacuum);

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

        let action = migrate(&transaction).unwrap();
        assert_eq!(action, PostMigrationAction::None);
    }
}
