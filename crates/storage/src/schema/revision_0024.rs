/// This migration adds following columns to `starknet_blocks` table:
/// - class_commitment
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tx.execute(
        "ALTER TABLE starknet_blocks ADD COLUMN class_commitment BLOB",
        [],
    )
    .context("Adding column: starknet_blocks.class_commitment")?;

    Ok(())
}
