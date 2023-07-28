use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Refactoring the headers table, this may take a while");

    tx.execute("ALTER TABLE starknet_blocks RENAME TO headers", [])
        .context("Renaming starknet_blocks table to headers")?;

    tx.execute(
        "ALTER TABLE headers RENAME COLUMN root TO storage_commitment",
        [],
    )
    .context("Renaming headers.root table to headers.storage_commitment")?;

    tx.execute(
        "ALTER TABLE headers ADD COLUMN state_commitment BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000'",
        [],
    )
    .context("Adding state_commitment column")?;

    tx.execute(
        "ALTER TABLE headers ADD COLUMN transaction_count INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .context("Adding transaction_count column")?;

    tx.execute(
        "ALTER TABLE headers ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .context("Adding event_count column")?;

    Ok(())
}
