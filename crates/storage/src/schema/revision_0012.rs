use anyhow::Context;
use rusqlite::Transaction;

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_events", [], |r| r.get(0))
        .context("Count rows in starknet events table")?;

    if todo == 0 {
        return Ok(());
    }

    tracing::info!(
        num_events=%todo,
        "Upgrading events table schema and re-indexing events, this may take a while.",
    );

    migrate_events_schema(transaction)
}

pub(super) fn migrate_events_schema(transaction: &Transaction<'_>) -> Result<(), anyhow::Error> {
    // When altering a table in a way that requires recreating it through copying and deletion
    // it is [recommended](https://www.sqlite.org/lang_altertable.html) to:
    // 1. create the new table with some temporary name
    // 2. copy the data from the old table
    // 3. drop the old table
    // 4. rename the new table
    // Instead of the opposite:
    // 1. rename the old table
    // 2. create the new table with the final name
    // 3. copy the data from the old table
    // 4. drop the old table
    //
    // Important notes:
    // 1. Triggers and indexes are dropped with the old `starknet_events` table,
    //    so they need to be recreated
    // 2. The virtual table `starknet_events_keys` needs to be recreated so that
    //    it uses the explicit `id` primary key of starknet_events as the content
    //    rowid (we're using starknet_events as external content table).
    transaction
        .execute_batch(
            r"
            -- Create new events table with a schema containing an integer primary key
            CREATE TABLE starknet_events_v2 (
                id INTEGER PRIMARY KEY NOT NULL,
                block_number  INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                transaction_hash BLOB NOT NULL,
                from_address BLOB NOT NULL,
                -- Keys are represented as base64 encoded strings separated by space
                keys TEXT,
                data BLOB,
                FOREIGN KEY(block_number) REFERENCES starknet_blocks(number)
                ON DELETE CASCADE
            );
            
            -- Copy event data from the old table
            INSERT INTO starknet_events_v2 (
                block_number,
                idx,
                transaction_hash,
                from_address,
                keys,
                data)
            
                SELECT
                    starknet_events.block_number,
                    starknet_events.idx,
                    starknet_events.transaction_hash,
                    starknet_events.from_address,
                    starknet_events.keys,
                    starknet_events.data
            
                FROM starknet_events;
            
            -- Drop old table and rename the new one
            DROP TABLE starknet_events;
            ALTER TABLE starknet_events_v2 RENAME TO starknet_events;",
        )
        .context("Recreating the starknet_events table and copying data")?;

    tracing::info!("Re-created the starknet_events table and copied data");

    transaction
        .execute_batch(
            r"
            -- Event filters can specify ranges of blocks
            CREATE INDEX starknet_events_block_number ON starknet_events(block_number);
            
            -- Event filter can specify a contract address
            CREATE INDEX starknet_events_from_address ON starknet_events(from_address);",
        )
        .context("Recreating indexes for starknet_events")?;

    tracing::info!("Re-created the indexes for starknet_events");

    transaction
        .execute_batch(r"
            -- Drop FTS5 virtual table containing key lookup data
            DROP TABLE starknet_events_keys;
            
            -- Re-create FTS5 virtual table as an external content table using `id` as the content rowid
            CREATE VIRTUAL TABLE starknet_events_keys
            USING fts5(
                keys,
                content='starknet_events',
                content_rowid='id',
                tokenize='ascii'
            );
            
            -- Re-populate the full text index with keys
            INSERT INTO starknet_events_keys (rowid, keys)
                SELECT starknet_events.id, starknet_events.keys
                FROM starknet_events;
            
            -- Re-create triggers updating the FTS5 table
            CREATE TRIGGER starknet_events_ai
            AFTER INSERT ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(rowid, keys)
                VALUES (
                    new.id,
                    new.keys
                );
            END;
            
            CREATE TRIGGER starknet_events_ad
            AFTER DELETE ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
                VALUES (
                    'delete',
                    old.id,
                    old.keys
                );
            END;
            
            CREATE TRIGGER starknet_events_au
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
            END;"
        )
        .context("Recreating the starknet_events_key FTS5 table and related triggers")?;

    tracing::info!("Re-created the full-text index for starknet_events");

    Ok(())
}
