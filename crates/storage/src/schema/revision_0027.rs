/// This migration removes the `contracts` table.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tx.execute("DROP TABLE contracts", [])
        .context("Removing table: contracts")?;

    Ok(())
}
