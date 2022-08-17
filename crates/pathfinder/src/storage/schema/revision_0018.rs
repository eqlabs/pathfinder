use anyhow::Context;
use rusqlite::Transaction;

/// Primary goal of this migration is to allow for StarkNet block forks.
///
/// This is achieved by re-creating the `starknet_blocks` table, shifting the PK
/// from `number` to `hash`. This in turn requires re-creating any tables with a FK
/// on the original `starknet_blocks` table.
///
/// In addition, a `canonical_blocks` table is created to track the canonical block chain
/// now that forks are allowed in `starknet_blocks`.
pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"-- Stores StarkNet block headers.
CREATE TABLE starknet_blocks_new (
    hash      BLOB    PRIMARY KEY NOT NULL,
    number    INTEGER NOT NULL,
    root      BLOB    NOT NULL,
    timestamp INTEGER NOT NULL, 
    gas_price BLOB    NOT NULL,
    sequencer_address BLOB NOT NULL,
    version_id INTEGER REFERENCES starknet_versions(id)
)",
        [],
    )
    .context("Creating new starknet_blocks table")?;

    tx.execute(
        "INSERT INTO starknet_blocks_new(hash,number,root,timestamp,gas_price) SELECT hash,number,root,timestamp,gas_price FROM starknet_blocks",
        [],
    )
    .context("Copying starknet_blocks data")?;

    create_canonical_chain(tx).context("Creating canonical_blocks table")?;
    migrate_state_updates(tx).context("Migrating starknet_state_updates table")?;
    migrate_events(tx).context("Migrating starknet_events table")?;

    tx.execute("DROP TABLE starknet_blocks", [])
        .context("Dropping old starknet_blocks table")?;
    tx.execute(
        "ALTER TABLE starknet_blocks_new RENAME TO starknet_blocks",
        [],
    )
    .context("Renaming new starknet_blocks table")?;

    Ok(())
}

/// Re-creates the `starknet_state_updates_new` table, updating the `block_hash` FK to
/// reference the new `starknet_blocks_new` table.
fn migrate_state_updates(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"-- Stores StarkNet state updates. 
CREATE TABLE starknet_state_updates_new (
    block_hash BLOB PRIMARY KEY NOT NULL,
    data BLOB NOT NULL,
    FOREIGN KEY(block_hash) REFERENCES starknet_blocks_new(hash) ON DELETE CASCADE
)",
        [],
    )
    .context("Creating new table")?;

    tx.execute(
        "INSERT INTO starknet_state_updates_new(block_hash, data) SELECT block_hash, data FROM starknet_state_updates",
        [],
    )
    .context("Copying data")?;

    tx.execute("DROP TABLE starknet_state_updates", [])
        .context("Dropping old table")?;
    tx.execute(
        "ALTER TABLE starknet_state_updates_new RENAME TO starknet_state_updates",
        [],
    )
    .context("Renaming new table")?;

    Ok(())
}

/// Re-creates the `starknet_events` events table, updating the `block_number` FK
/// to reference the `canonical_blocks` table instead.
fn migrate_events(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"CREATE TABLE starknet_events_new (
    block_number  INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    transaction_hash BLOB NOT NULL,
    from_address BLOB NOT NULL,
    -- Keys are represented as base64 encoded strings separated by space
    keys TEXT,
    data BLOB,
    FOREIGN KEY(block_number) REFERENCES canonical_blocks(number) ON DELETE CASCADE
)",
        [],
    )
    .context("Creating new table")?;

    tx.execute(
        r"-- Copy rowids to be sure that starknet_events_keys still references valid rows
INSERT INTO starknet_events_new (rowid,block_number,idx,transaction_hash,from_address,keys,data)
    SELECT rowid,block_number,idx,transaction_hash,from_address,keys,data FROM starknet_events",
        [],
    )
    .context("Copying data")?;

    // CREATE INDEX starknet_events_block_number ON starknet_events(block_number);
    // CREATE INDEX starknet_events_from_address ON starknet_events(from_address);

    tx.execute("DROP TABLE starknet_events", [])
        .context("Dropping old table")?;

    tx.execute(
        "ALTER TABLE starknet_events_new RENAME TO starknet_events",
        [],
    )
    .context("Renaming new table")?;

    // Re-create triggers.
    tx.execute(
        r"CREATE TRIGGER starknet_events_ai
    AFTER INSERT ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.rowid,
            new.keys
        );
    END;",
        [],
    )
    .context("Creating after insert trigger")?;

    tx.execute(
        r"CREATE TRIGGER starknet_events_ad
    AFTER DELETE ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
        VALUES (
            'delete',
            old.rowid,
            old.keys
        );
    END;",
        [],
    )
    .context("Creating delete trigger")?;

    tx.execute(
        r"CREATE TRIGGER starknet_events_au
    AFTER UPDATE ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
        VALUES (
            'delete',
            old.rowid,
            old.keys
        );
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.rowid,
            new.keys
        );
    END;",
        [],
    )
    .context("Creating update trigger")?;

    // Re-create indexs
    tx.execute(
        "CREATE INDEX starknet_events_block_number ON starknet_events(block_number)",
        [],
    )
    .context("Creating block_number index")?;
    tx.execute(
        "CREATE INDEX starknet_events_from_address ON starknet_events(from_address)",
        [],
    )
    .context("Creating from_address index")?;

    Ok(())
}

/// Creates a new `canonical_blocks` table which holds the canonical StarkNet block chain.
fn create_canonical_chain(tx: &Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"-- Holds StarkNet's current canonical chain of blocks.
CREATE TABLE canonical_blocks (
    number INTEGER PRIMARY KEY NOT NULL,
    hash   BLOB    NOT NULL,
    FOREIGN KEY(hash) REFERENCES starknet_blocks_new(hash)
)",
        [],
    )
    .context("Creating table")?;
    tx.execute(
        "INSERT INTO canonical_blocks (number,hash) SELECT number, hash FROM starknet_blocks_new",
        [],
    )
    .context("Inserting data")?;

    Ok(())
}
