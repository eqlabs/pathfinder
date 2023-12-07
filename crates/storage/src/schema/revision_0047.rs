use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::OptionalExtension;

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

    // Create an index on the address to make reverse lookups fast. This is important to do
    // before we start migrating existing data from address to idx.
    tx.execute(
        "CREATE INDEX storage_addresses_address ON storage_addresses(address)",
        [],
    )
    .context("Creating index on storage_addresses(address)")?;

    // Approximate number of rows using rowid. This is much faster than doing it with COUNT(1),
    // and will be more than the actual count.
    let count: usize = tx
        .query_row(
            "SELECT rowid FROM storage_updates ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("Querying storage count")?
        .unwrap_or_default();

    tracing::info!(
        rows = count,
        "Copying storage addresses to new table, this may take a while"
    );

    let mut stmt = tx
        .prepare("SELECT storage_address FROM storage_updates")
        .context("Preparing read statement")?;

    let rows = stmt
        .query_map([], |row| row.get(0))
        .context("Querying read statement")?;

    let mut addresses = HashSet::new();
    let mut t = Instant::now();
    for (idx, row) in rows.enumerate() {
        let address: [u8; 32] = row?;
        addresses.insert(address);

        if t.elapsed() > LOG_PERIOD {
            t = Instant::now();

            let progress = idx as f32 / count as f32 * 100.0;

            tracing::info!("Collecting storage addresses. Progress: {progress:3.2}%");
        }
    }
    let count = addresses.len();
    tracing::info!("Writing {count} addresses to new table");

    let mut stmt = tx
        .prepare("INSERT INTO storage_addresses(address) VALUES(?)")
        .context("Preparing write statement")?;

    for (idx, address) in addresses.into_iter().enumerate() {
        stmt.execute([&address]).context("Inserting address")?;

        if t.elapsed() > LOG_PERIOD {
            t = Instant::now();

            let progress = idx as f32 / count as f32 * 100.0;

            tracing::info!("Writing storage addresses. Progress: {progress:3.2}%");
        }
    }

    Ok(())
}
