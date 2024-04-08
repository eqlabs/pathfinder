use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
        CREATE TABLE trie_class_removals (
            block_number INTEGER PRIMARY KEY,
            indices BLOB
        );
        CREATE TABLE trie_contracts_removals (
            block_number INTEGER PRIMARY KEY,
            indices BLOB
        );
        CREATE TABLE trie_storage_removals (
            block_number INTEGER PRIMARY KEY,
            indices BLOB
        );
        ",
    )
    .context("Creating removals tables")?;

    Ok(())
}
