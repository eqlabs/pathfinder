/// This migration adds following columns to `starknet_blocks` table:
/// - transaction_commitment
/// - event_commitment
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tx.execute(
        "ALTER TABLE starknet_blocks ADD COLUMN transaction_commitment BLOB",
        [],
    )
    .context("Adding column: starknet_blocks.transaction_commitment")?;

    tx.execute(
        "ALTER TABLE starknet_blocks ADD COLUMN event_commitment BLOB",
        [],
    )
    .context("Adding column: starknet_blocks.event_commitment")?;

    Ok(())
}
