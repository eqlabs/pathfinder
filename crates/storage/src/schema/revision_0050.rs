use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
ALTER TABLE starknet_transactions ADD CONSTRAINT unique_idx_and_block_hash UNIQUE (idx, block_hash);
",
    )
    .context("Adding new columns to block_headers")?;

    Ok(())
}
