use anyhow::Context;
use rusqlite::Transaction;

/// Adds the `starknet_versions` table following introduction of
/// [`starknet_gateway_types::reply::Block::starknet_version`].
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // using UNIQUE on the column does have the downside of it not being droppable
    // but assuming we will not need this table for anything else, it might be ok
    transaction
        .execute(
            "CREATE TABLE starknet_versions (id INTEGER NOT NULL PRIMARY KEY, version TEXT NOT NULL UNIQUE)",
            [],
        )
        .context("Failed to create new table 'starknet_versions'")?;

    transaction
        .execute(
            "ALTER TABLE starknet_blocks ADD COLUMN version_id INTEGER REFERENCES starknet_versions(id)",
            []
        ).context("Failed to add column to 'starknet_blocks'")?;

    Ok(())
}
