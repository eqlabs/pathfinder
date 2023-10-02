use anyhow::Context;

/// This migration replaces the hash-index'd tree tables with integer ones.
///
/// Because this is the first migration post-base, we are guaranteed that there is no
/// data to migrate.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    drop_table(tx, "tree_class").context("Dropping tree_class table")?;
    drop_table(tx, "tree_global").context("Dropping tree_global table")?;
    drop_table(tx, "tree_contracts").context("Dropping tree_contracts table")?;

    create_trie_table(tx, "trie_class").context("Creating trie_class table")?;
    create_trie_table(tx, "trie_storage").context("Creating trie_storage table")?;
    create_trie_table(tx, "trie_contracts").context("Creating trie_contracts table")?;

    create_roots_table(tx, "class_roots").context("Creating class_roots table")?;
    create_roots_table(tx, "storage_roots").context("Creating storage_roots table")?;

    tx.execute(
        r"CREATE TABLE contract_roots (
    block_number     INTEGER NOT NULL,
    contract_address BLOB NOT NULL,
    root_index       INTEGER NOT NULL
)",
        [],
    )
    .context("Creating class_roots table")?;

    tx.execute(
        "CREATE INDEX contract_roots_address_block_number ON contract_roots(contract_address, block_number)", []
    )
    .context("Creating contract_roots_address_block_number index")?;

    Ok(())
}

fn drop_table(tx: &rusqlite::Transaction<'_>, table: &'static str) -> anyhow::Result<()> {
    tx.execute(&format!("DROP TABLE {table}"), [])?;
    Ok(())
}

fn create_trie_table(tx: &rusqlite::Transaction<'_>, table: &'static str) -> anyhow::Result<()> {
    tx.execute(
        &format!(
            r"CREATE TABLE {table} (
    idx INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    data BLOB
)"
        ),
        [],
    )?;
    Ok(())
}

fn create_roots_table(tx: &rusqlite::Transaction<'_>, table: &'static str) -> anyhow::Result<()> {
    tx.execute(
        &format!(
            r"CREATE TABLE {table} (
    block_number INTEGER PRIMARY KEY,
    root_index   INTEGER NOT NULL
)"
        ),
        [],
    )?;
    Ok(())
}
