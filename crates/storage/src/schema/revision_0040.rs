use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    create_table(tx, "trie_class").context("Creating trie_class table")?;
    create_table(tx, "trie_storage").context("Creating trie_storage table")?;
    create_table(tx, "trie_contracts").context("Creating trie_contracts table")?;

    // TODO: drop the original tables..

    Ok(())
}

fn create_table(tx: &rusqlite::Transaction<'_>, table: &'static str) -> anyhow::Result<()> {
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
