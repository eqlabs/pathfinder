use anyhow::Context;

/// This migration adds a table to track a contract roots over time.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"CREATE TABLE contract_roots (
    block_number      INTEGER NOT NULL,
    contract_address  BLOB NOT NULL,
    contract_root     BLOB NOT NULL
)",
        [],
    )
    .context("Creating contract_roots table")?;

    tx.execute("DROP TABLE contract_states", [])
        .context("Dropping contract_states table")?;

    Ok(())
}
