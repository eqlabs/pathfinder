use anyhow::Context;

/// This migration creates the table for the Merke trees.
///
/// Normally this is not necessary (because opening the tree will automatically
/// create the tables), but for tests it's useful because otherwise the Python
/// subprocess will just throw errors.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"CREATE TABLE IF NOT EXISTS tree_global (
            hash        BLOB PRIMARY KEY,
            data        BLOB,
            ref_count   INTEGER
        );",
    )
    .context("Adding tree_global table")?;

    tx.execute_batch(
        r"CREATE TABLE IF NOT EXISTS tree_contracts (
            hash        BLOB PRIMARY KEY,
            data        BLOB,
            ref_count   INTEGER
        );",
    )
    .context("Adding tree_contracts table")?;

    tx.execute_batch(
        r"CREATE TABLE IF NOT EXISTS tree_class (
            hash        BLOB PRIMARY KEY,
            data        BLOB,
            ref_count   INTEGER
        );",
    )
    .context("Adding tree_class table")?;

    Ok(())
}
