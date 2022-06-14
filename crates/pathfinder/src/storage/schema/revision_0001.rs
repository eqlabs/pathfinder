use rusqlite::Transaction;

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    transaction.execute(
        r"CREATE TABLE contract_code (
            hash       BLOB PRIMARY KEY,
            bytecode   BLOB,
            abi        BLOB,
            definition BLOB
        )",
        [],
    )?;
    transaction.execute(
        r"CREATE TABLE contracts (
            address    BLOB PRIMARY KEY,
            hash       BLOB NOT NULL,

            FOREIGN KEY(hash) REFERENCES contract_code(hash)
        )",
        [],
    )?;
    transaction.execute(
        r"CREATE TABLE ethereum_blocks (
            hash   BLOB PRIMARY KEY,
            number INTEGER NOT NULL
        )",
        [],
    )?;
    transaction.execute(
        r"CREATE TABLE ethereum_transactions (
            hash       BLOB PRIMARY KEY,
            idx        INTEGER NOT NULL,
            block_hash BLOB NOT NULL,

            FOREIGN KEY(block_hash) REFERENCES ethereum_blocks(hash)
        )",
        [],
    )?;
    transaction.execute(
        r"CREATE TABLE global_state (
            starknet_block_hash       BLOB PRIMARY KEY,
            starknet_block_number     INTEGER NOT NULL,
            starknet_block_timestamp  INTEGER NOT NULL,
            starknet_global_root      BLOB NOT NULL,
            ethereum_transaction_hash BLOB NOT NULL,
            ethereum_log_index        INTEGER NOT NULL,

            FOREIGN KEY(ethereum_transaction_hash) REFERENCES ethereum_transactions(hash)
        )",
        [],
    )?;
    transaction.execute(
        r"CREATE TABLE contract_states (
            state_hash BLOB PRIMARY KEY,
            hash       BLOB NOT NULL,
            root       BLOB NOT NULL
        )",
        [],
    )?;

    Ok(())
}
