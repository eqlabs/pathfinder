use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::OptionalExtension;

use crate::params::params;
use crate::params::RowExt;

const LOG_PERIOD: Duration = Duration::from_secs(10);

/// This migration adds interning for storages addresses which can be used in
/// future migrat8ions to save space in existing tables as a FK.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"CREATE TABLE storage_addresses (
    idx     INTEGER PRIMARY KEY,
    address BLOB NOT NULL
)",
        [],
    )
    .context("Creating storage_addresses table")?;

    // Create an index on the address to make reverse lookups fast.
    tx.execute(
        "CREATE INDEX storage_addresses_address ON storage_addresses(address)",
        [],
    )
    .context("Creating index on storage_addresses(address)")?;

    tx.execute(
        "ALTER TABLE storage_updates RENAME TO storage_updates_old",
        [],
    )
    .context("Renaming storage_updates table")?;

    // Create new table with the same indexes.
    tx.execute_batch(
        r"CREATE TABLE storage_updates (
    block_number  INTEGER NOT NULL REFERENCES canonical_blocks(number) ON DELETE CASCADE,
    contract_idx  INTEGER NOT NULL REFERENCES contract_addresses(idx),
    storage_idx   INTEGER NOT NULL REFERENCES storage_addresses(idx),
    storage_value BLOB    NOT NULL
);
CREATE INDEX storage_updates_contract_storage_block ON storage_updates(contract_idx, storage_idx, block_number);
CREATE INDEX storage_updates_block ON storage_updates(block_number);"
    )
    .context("Creating new storage_updates table")?;

    // Approximate number of rows using rowid. This is much faster than doing it with COUNT(1),
    // and will be more than the actual count.
    let count: usize = tx
        .query_row(
            "SELECT rowid FROM storage_updates_old ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("Querying storage count")?
        .unwrap_or_default();

    tracing::info!(
        rows = count,
        "Migrating storage updates to new table, this may take a while"
    );

    let mut read = tx
        .prepare(
            r"SELECT block_number, contract_addresses.idx, storage_address, storage_value 
                FROM storage_updates_old
                JOIN contract_addresses ON(storage_updates_old.contract_address = contract_addresses.address)"
        )
        .context("Preparing read query")?;

    let mut intern = tx
        .prepare("INSERT INTO storage_addresses(address) VALUES(?) RETURNING idx")
        .context("Preparing storage address interning statement")?;

    let mut write = tx
        .prepare(
            r"INSERT INTO storage_updates(block_number, contract_idx, storage_idx, storage_value) 
                VALUES(?,?,?,?)",
        )
        .context("Preparing write statement")?;

    let mut key_cache = HashMap::new();

    let rows = read
        .query_map([], |row| {
            let number = row.get_block_number(0)?;
            let contract: u64 = row.get(1)?;
            let key = row.get_storage_address(2)?;
            let value = row.get_storage_value(3)?;

            Ok((number, contract, key, value))
        })
        .context("Querying storage updates")?;

    let mut t = Instant::now();
    for (idx, row) in rows.enumerate() {
        let (number, contract, key, value) = row?;

        let key_idx: u64 = if let Some(key_idx) = key_cache.get(&key) {
            *key_idx
        } else {
            let key_idx = intern
                .query_row(params![&key], |row| row.get(0))
                .context("Interning storage key")?;

            key_cache.insert(key, key_idx);
            key_idx
        };

        write
            .execute(params![&number, &contract, &key_idx, &value])
            .context("Inserting storage update")?;

        if t.elapsed() > LOG_PERIOD {
            t = Instant::now();

            let progress = idx as f32 / count as f32 * 100.0;

            tracing::info!("Copying storage updates. Progress: {progress:3.2}%");
        }
    }

    anyhow::bail!("oof");

    Ok(())
}
