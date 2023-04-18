pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch("DROP TABLE l1_state")
        .context("Drop table l1_state")?;

    Ok(())
}
