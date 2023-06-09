use anyhow::Context;

/// Ensures the trie reference counts are not NULL by setting these to 1.
///
/// The nulls came about because reference counting was stopped for a releases,
/// during which new nodes were inserted with ref_count=NULL. Since we are now
/// starting reference counting again, these NULLs should be an integer so they
/// can be incremented / decremented via sql.
///
/// Due to this skipping of reference counting, it is not yet safe to delete / purge node
/// data. Another migration will be requried to rewrite the trie data with accurate ref counts
/// before it is safe to delete.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        "UPDATE tree_contracts SET ref_count=1 WHERE ref_count IS NULL;",
        [],
    )
    .context("Replacing contract trie NULL reference counts")?;

    tx.execute(
        "UPDATE tree_class SET ref_count=1 WHERE ref_count IS NULL;",
        [],
    )
    .context("Replacing class trie NULL reference counts")?;

    tx.execute(
        "UPDATE tree_global SET ref_count=1 WHERE ref_count IS NULL;",
        [],
    )
    .context("Replacing global storage trie NULL reference counts")?;

    Ok(())
}
