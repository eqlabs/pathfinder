use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    create_trie_table(tx, "trie_class").context("Creating trie_class table")?;
    create_trie_table(tx, "trie_storage").context("Creating trie_storage table")?;
    create_trie_table(tx, "trie_contracts").context("Creating trie_contracts table")?;

    // TODO: drop the original tree tables..

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

fn create_trie_table(tx: &rusqlite::Transaction<'_>, table: &'static str) -> anyhow::Result<()> {
    tx.execute(
        &format!(
            r"CREATE TABLE {table} (
    idx INTEGER PRIMARY KEY,
    hash BLOB NOT NULL,
    data BLOB NOT NULL
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
