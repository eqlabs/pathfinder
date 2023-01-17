use anyhow::Context;
use rusqlite::Transaction;

/// Adds a new FTS5 index for looking up events based on keys.
///
/// The new JSON-RPC 0.3 `starknet_getEvents` semantics mean we need to construct
/// FTS5 expressions that match on keys in specific positions in the event.
///
/// We use a scheme where each key is prefixed with its position in the event (a single u8) and
/// the resulting 33 byte binary representation is then converted to non-padded Base32 encoding.
/// Space separated lists of encoded strings are then inserted into the full-text index.
pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let row_count: usize = tx
        .query_row("SELECT count(1) FROM starknet_events", [], |r| r.get(0))
        .context("Count rows in starknet_events table")?;

    if row_count > 0 {
        tracing::info!(
            %row_count,
            "Creating new index for event keys, this might take a while",
        );
    }

    tx.execute_batch(
        r"
        -- Create an FTS5 virtual table as a contentless table indexing index-prefixed keys
        CREATE VIRTUAL TABLE starknet_events_keys_03
        USING fts5(
            keys,
            content='',
            tokenize='ascii'
        );

        -- Re-populate the full text index with keys
        INSERT INTO starknet_events_keys_03 (rowid, keys)
            SELECT
                starknet_events.id,
                base64_felts_to_index_prefixed_base32_felts(starknet_events.keys)
            FROM starknet_events;

        -- Re-create triggers updating the FTS5 table
        CREATE TRIGGER starknet_events_03_ai
        AFTER INSERT ON starknet_events
        BEGIN
            INSERT INTO starknet_events_keys_03(rowid, keys)
            VALUES (
                new.id,
                base64_felts_to_index_prefixed_base32_felts(new.keys)
            );
        END;

        CREATE TRIGGER starknet_events_03_ad
        AFTER DELETE ON starknet_events
        BEGIN
            INSERT INTO starknet_events_keys_03(starknet_events_keys_03, rowid, keys)
            VALUES (
                'delete',
                old.id,
                base64_felts_to_index_prefixed_base32_felts(old.keys)
            );
        END;

        CREATE TRIGGER starknet_events_03_au
        AFTER UPDATE ON starknet_events
        BEGIN
            INSERT INTO starknet_events_keys_03(starknet_events_keys_03, rowid, keys)
            VALUES (
                'delete',
                old.id,
                base64_felts_to_index_prefixed_base32_felts(old.keys)
            );
            INSERT INTO starknet_events_keys_03(rowid, keys)
            VALUES (
                new.id,
                base64_felts_to_index_prefixed_base32_felts(new.keys)
            );
        END;",
    )
    .context("Creating the starknet_events_key_03 FTS5 table and related triggers")?;

    tracing::info!("Created event key index with new lookup semantics for starknet_events");

    Ok(())
}
