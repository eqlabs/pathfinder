use rusqlite::{params, OptionalExtension, Transaction};

/// This schema migration splits the global state table into
/// separate tables containing L1 and L2 data.
///
/// In addition, it also adds a refs table which only contains a single column.
/// This columns references the latest Starknet block for which the L1 and L2
/// states are the same.
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // Create the new L1 table.
    transaction.execute(
        r"CREATE TABLE l1_state (
            starknet_block_number      INTEGER PRIMARY KEY,
            starknet_global_root       BLOB    NOT NULL,
            ethereum_block_hash        BLOB    NOT NULL,
            ethereum_block_number      INTEGER NOT NULL,
            ethereum_transaction_hash  BLOB    NOT NULL,
            ethereum_transaction_index INTEGER NOT NULL,
            ethereum_log_index         INTEGER NOT NULL
        )",
        [],
    )?;

    // Create the new L2 table
    transaction.execute(
        r"CREATE TABLE starknet_blocks (
            number               INTEGER PRIMARY KEY,
            hash                 BLOB    NOT NULL,
            root                 BLOB    NOT NULL,
            timestamp            INTEGER NOT NULL,
            transactions         BLOB,
            transaction_receipts BLOB
        )",
        [],
    )?;

    // Add new L1 L2 state table. This will track the latest Starknet block
    // for which L1 and L2 agree.
    transaction.execute(
        "CREATE TABLE refs (idx INTEGER PRIMARY KEY, l1_l2_head BLOB)",
        [],
    )?;

    // Migrate existing L1 data.
    transaction.execute(
        r"INSERT INTO l1_state (
            starknet_block_number,
            starknet_global_root,
            ethereum_block_hash,
            ethereum_block_number,
            ethereum_transaction_hash,
            ethereum_transaction_index,
            ethereum_log_index)

        SELECT global_state.starknet_block_number,
               global_state.starknet_global_root,
               ethereum_blocks.hash,
               ethereum_blocks.number,
               ethereum_transactions.hash,
               ethereum_transactions.idx,
               global_state.ethereum_log_index

        FROM global_state
        JOIN ethereum_transactions ON global_state.ethereum_transaction_hash = ethereum_transactions.hash
        JOIN ethereum_blocks ON ethereum_transactions.block_hash = ethereum_blocks.hash",
        [],
    )?;

    // Migrate existing L2 data. Transactions are left empty, since we
    // did not store this data yet. This does not require re-downloading
    // as these migrations only affect developer data.
    transaction.execute(
        r"INSERT INTO starknet_blocks (number, hash, root, timestamp)
        SELECT old.starknet_block_number,
               old.starknet_block_hash,
               old.starknet_global_root,
               old.starknet_block_timestamp
        FROM global_state old",
        [],
    )?;

    // Get the latest starknet block number and set the L1-L2 head reference to it.
    // This will default to null if no such number exists at all.
    //
    // This latest block is the L1-L2 head because schema 2 tracked L1 and L2 in lock-step.
    let latest: Option<u64> = transaction
        .query_row(
            r"SELECT starknet_block_number FROM global_state
        ORDER BY starknet_block_number DESC
        LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    transaction.execute(
        "INSERT INTO refs (idx, l1_l2_head) VALUES (?, ?)",
        params![1, latest],
    )?;

    // drop the old state table and ethereum tables.
    transaction.execute("DROP TABLE global_state", [])?;
    transaction.execute("DROP TABLE ethereum_transactions", [])?;
    transaction.execute("DROP TABLE ethereum_blocks", [])?;

    Ok(())
}
