use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch("ALTER TABLE starknet_transactions DROP COLUMN execution_status;")
        .context("Dropping execution_status column")
}
