use anyhow::Context;
use rusqlite::Transaction;

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // We need to check if this db needs fixing at all
    let update_is_not_required = {
        let mut stmt = transaction
            .prepare("SELECT sql FROM sqlite_schema where tbl_name = 'starknet_events'")
            .context("Preparing statement")?;
        let mut rows = stmt.query([]).context("Executing query")?;
        // Unwrap is safe because the schema for this table obviously contains more than
        // zero SQL statements, as can be seen in revision 7 migration.
        // The first statement of the schema for this table is the creation of the table
        // which could be missing the crucial action, which is ON DELETE CASCADE.
        rows.next()?
            .unwrap()
            .get_ref_unwrap("sql")
            .as_str()?
            .contains("ON DELETE CASCADE")
    };

    if update_is_not_required {
        return Ok(());
    }

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
    // 2. The virtual table `starknet_events_keys` remains unchanged but:
    //    - we need to make sure that the new `starknet_events` table
    //      [keeps the same rowids](https://www.sqlite.org/fts5.html#external_content_tables)
    //      as its older version
    //    - otherwise `starknet_events_keys` could refer invalid rowids
    //    - rendering future event queries unreliable
    transaction
        .execute_batch(
            r"
            CREATE TABLE starknet_events_v2 (
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

            -- Copy rowids to be sure that starknet_events_keys still references valid rows
            INSERT INTO starknet_events_v2 (
                rowid,
                block_number,
                idx,
                transaction_hash,
                from_address,
                keys,
                data)

                SELECT starknet_events.rowid,
                    starknet_events.block_number,
                    starknet_events.idx,
                    starknet_events.transaction_hash,
                    starknet_events.from_address,
                    starknet_events.keys,
                    starknet_events.data

                FROM starknet_events;

            DROP TABLE starknet_events;

            ALTER TABLE starknet_events_v2 RENAME TO starknet_events;

            -- Event filters can specify ranges of blocks
            CREATE INDEX starknet_events_block_number ON starknet_events(block_number);

            -- Event filter can specify a contract address
            CREATE INDEX starknet_events_from_address ON starknet_events(from_address);

            CREATE TRIGGER starknet_events_ai
            AFTER INSERT ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(rowid, keys)
                VALUES (
                    new.rowid,
                    new.keys
                );
            END;

            CREATE TRIGGER starknet_events_ad
            AFTER DELETE ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
                VALUES (
                    'delete',
                    old.rowid,
                    old.keys
                );
            END;

            CREATE TRIGGER starknet_events_au
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
        )
        .context("Recreating the starknet_events table, related triggers and indexes")?;

    Ok(())
}
