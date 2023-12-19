use crate::{bloom::BloomFilter, params::RowExt};

use anyhow::Context;
use rusqlite::params;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    //     tx.execute_batch(
    //         r"
    // CREATE TABLE starknet_events_keys (
    //     id INTEGER PRIMARY KEY NOT NULL,
    //     key BLOB UNIQUE NOT NULL
    // );

    // CREATE TABLE starknet_events_data (
    //     id INTEGER PRIMARY KEY NOT NULL,
    //     data BLOB UNIQUE NOT NULL
    // );

    // CREATE TABLE starknet_events_from_addresses (
    //     id INTEGER PRIMARY KEY NOT NULL,
    //     address BLOB UNIQUE NOT NULL
    // );

    // CREATE TABLE starknet_events_new (
    //     id INTEGER PRIMARY KEY NOT NULL,
    //     block_number  INTEGER NOT NULL,
    //     idx INTEGER NOT NULL,
    //     transaction_idx INTEGER NOT NULL,
    //     from_address INTEGER NOT NULL,
    //     keys BLOB,
    //     data BLOB,
    //     FOREIGN KEY(block_number) REFERENCES canonical_blocks(number) ON DELETE CASCADE
    // );
    // ",
    //     )
    //     .context("Creating new event tables")?;

    tx.execute_batch(
        r"
        CREATE TABLE starknet_events_filters (
            block_number INTEGER NOT NULL PRIMARY KEY,
            bloom BLOB NOT NULL
        );
    ",
    )
    .context("Creating event Bloom filter table")?;

    let mut query_statement = tx.prepare(
        r"SELECT
        block_headers.number as block_number,
        idx,
        tx,
        receipt
    FROM starknet_transactions
    INNER JOIN block_headers ON (starknet_transactions.block_hash = block_headers.hash)
    ORDER BY block_number
    ",
    )?;

    let mut insert_statement =
        tx.prepare(r"INSERT INTO starknet_events_filters (block_number, bloom) VALUES (?, ?)")?;

    let mut rows = query_statement.query([])?;

    let mut last_block_number: u64 = 0;
    let mut bloom = BloomFilter::new();
    let mut events_in_filter: usize = 0;

    while let Some(row) = rows.next().context("Fetching next receipt")? {
        let block_number = row.get_block_number("block_number")?;

        let current_block_number = block_number.get();
        if current_block_number > last_block_number {
            if current_block_number % 10000 == 0 {
                tracing::debug!(%current_block_number, "Processing events");
            }

            insert_statement.execute(params![last_block_number, bloom.as_compressed_bytes()])?;

            bloom = BloomFilter::new();
            last_block_number = current_block_number;
            events_in_filter = 0;
        }

        let receipt = row
            .get_ref_unwrap("receipt")
            .as_blob()
            .map_err(anyhow::Error::from)?;
        let receipt = zstd::decode_all(receipt).context("Decompressing transaction receipt")?;
        let receipt: starknet_gateway_types::reply::transaction::Receipt =
            serde_json::from_slice(&receipt).context("Deserializing transaction receipt")?;

        for event in receipt.events {
            for (i, key) in event.keys.iter().enumerate() {
                // FIXME
                assert!(i < 16);
                let mut key = key.0;
                key.as_mut_be_bytes()[0] |= (i as u8) << 4;
                bloom.set(&key);
            }

            bloom.set(&event.from_address.0);

            events_in_filter += 1;
        }
    }
    if events_in_filter > 0 {
        insert_statement.execute(params![last_block_number, bloom.as_compressed_bytes()])?;
    }

    Ok(())
}
