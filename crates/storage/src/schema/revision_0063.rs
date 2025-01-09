use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Adding index for block signatures");

    tx.execute_batch(
        "CREATE UNIQUE INDEX block_signatures_block_number ON block_signatures(block_number);",
    )
    .context("Adding block_signatures(block_number) index")?;

    Ok(())
}
