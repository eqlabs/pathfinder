use rusqlite::Transaction;

pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute("DROP TABLE l1_state", [])?;
    tx.execute(
        r"CREATE TABLE l1_state (
            starknet_block_number      INTEGER PRIMARY KEY,
            starknet_block_hash        BLOB    NOT NULL,
            starknet_global_root       BLOB    NOT NULL
        )",
        [],
    )?;

    Ok(())
}
