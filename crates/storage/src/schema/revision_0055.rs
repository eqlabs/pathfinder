use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
        CREATE TABLE trie_class_removals (
            block_number INTEGER,
            indices BLOB
        );
        CREATE INDEX trie_class_removals_block_number ON trie_class_removals(block_number);
        CREATE TABLE trie_contracts_removals (
            block_number INTEGER,
            indices BLOB
        );
        CREATE INDEX trie_contracts_removals_block_number ON trie_contracts_removals(block_number);
        CREATE TABLE trie_storage_removals (
            block_number INTEGER,
            indices BLOB
        );
        CREATE INDEX trie_storage_removals_block_number ON trie_storage_removals(block_number);
        ",
    )
    .context("Creating removals tables")?;

    Ok(())
}
