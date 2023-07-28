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

    Ok(())
}
