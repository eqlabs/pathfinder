use anyhow::Context;
use rusqlite::Transaction;

/// Primary goal of this migration is to allow for StarkNet block forks.
///
/// This is achieved by:
/// - switching `starknet_blocks` table PK from block number to hash
/// - adding a `canonical_blocks` table to track the canonical chain
/// - `starknet_events` now references `canonical_blocks` instead of `starknet_blocks`
pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
    let fk_config = tx
        .db_config(SQLITE_DBCONFIG_ENABLE_FKEY)
        .context("Reading FK configuration")?;
    tx.set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, false)
        .context("Disabling foreign-key enforcement")?;

    migrate_blocks(tx).context("Migrating starknet_blocks table")?;
    create_canonical_chain(tx).context("Creating canonical_blocks table")?;
    migrate_events(tx).context("Migrating starknet_events table")?;

    tx.set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, fk_config)
        .context("Setting FK enforcement to pre-migration value")?;

    Ok(())
}

fn migrate_blocks(tx: &Transaction<'_>) -> anyhow::Result<()> {
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
    .context("Creating new table")?;

    tx.execute(
        r"INSERT INTO starknet_blocks_new(hash,number,root,timestamp,gas_price,sequencer_address,version_id) 
                                   SELECT hash,number,root,timestamp,gas_price,sequencer_address,version_id FROM starknet_blocks",
        [],
    )
    .context("Copying data")?;

    tx.execute("DROP TABLE starknet_blocks", [])
        .context("Dropping old table")?;

    tx.execute(
        "ALTER TABLE starknet_blocks_new RENAME TO starknet_blocks",
        [],
    )
    .context("Renaming table")?;

    tx.execute(
        "CREATE INDEX starknet_blocks_block_number ON starknet_blocks(number)",
        [],
    )
    .context("Creating block_number index")?;

    Ok(())
}

/// Re-creates the `starknet_events` events table, updating the `block_number` FK
/// to reference the `canonical_blocks` table instead.
fn migrate_events(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let row_count: usize = tx
        .query_row("SELECT count(1) FROM starknet_events", [], |r| r.get(0))
        .context("Count rows in starknet_events table")?;

    if row_count > 0 {
        tracing::info!(
            %row_count,
            "Migrating events table, this may take a while",
        );
    }

    tx.execute(
        r"CREATE TABLE starknet_events_new (
    id INTEGER PRIMARY KEY NOT NULL,
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

    // The related FTS5 table does not need to be rebuilt as it references `starknet_events.id` which we are copying
    // verbatim here.
    tx.execute(
        r"INSERT INTO starknet_events_new (id,block_number,idx,transaction_hash,from_address,keys,data)
    SELECT id,block_number,idx,transaction_hash,from_address,keys,data FROM starknet_events",
        [],
    )
    .context("Copying data")?;

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
            new.id,
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
            old.id,
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
            old.id,
            old.keys
        );
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.id,
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
    FOREIGN KEY(hash) REFERENCES starknet_blocks(hash)
)",
        [],
    )
    .context("Creating table")?;

    tx.execute(
        "INSERT INTO canonical_blocks (number,hash) SELECT number, hash FROM starknet_blocks",
        [],
    )
    .context("Inserting data")?;

    Ok(())
}
