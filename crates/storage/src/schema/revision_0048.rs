use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::OptionalExtension;

const LOG_PERIOD: Duration = Duration::from_secs(10);

/// This migration re-creates the storage_updates table to use the contract and
/// storage address interning tables. The table is create anew instead of altered
/// to avoid missing constraints.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
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
        .context("Querying row count")?
        .unwrap_or_default();

    tracing::info!(
        rows = count,
        "Copying storage_updates to new table, this may take a while"
    );

    let mut read = tx.prepare(r"SELECT block_number, contract_addresses.idx, storage_addresses.idx, storage_value 
        FROM storage_updates_old 
            JOIN contract_addresses ON(storage_updates_old.contract_address = contract_addresses.address)
            JOIN storage_addresses  ON(storage_updates_old.storage_address  = storage_addresses.address)"
    )
    .context("Preparing read query")?;

    let mut write = tx
        .prepare("INSERT INTO storage_updates(block_number,contract_idx,storage_idx,storage_value) VALUES(?,?,?,?)")
        .context("Preparing write statement")?;

    let rows = read
        .query_map([], |row| {
            let number: u64 = row.get(0)?;
            let contract_idx: u64 = row.get(1)?;
            let storage_idx: u64 = row.get(2)?;
            let storage_value: Vec<u8> = row.get(3)?;

            Ok((number, contract_idx, storage_idx, storage_value))
        })
        .context("Querying read statement")?;

    let mut t = Instant::now();
    for (idx, row) in rows.enumerate() {
        let (number, contract, key, value) = row?;
        write.execute(rusqlite::params![number, contract, key, value])?;

        if t.elapsed() > LOG_PERIOD {
            t = Instant::now();
            let progress = idx as f32 / count as f32 * 100.0;
            tracing::info!("Copying storage updates. Progress: {progress:3.2}%");
        }
    }

    tracing::info!("Dropping original table, this may take a while");

    tx.execute("DROP TABLE storage_updates_old", [])
        .context("Dropping original table")?;

    Ok(())
}
