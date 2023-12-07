use std::collections::HashSet;

use crate::params::RowExt;

use anyhow::Context;

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

    let mut query_statement = tx.prepare(
        r"SELECT
        block_headers.number as block_number,
        idx,
        receipt
    FROM starknet_transactions
    INNER JOIN block_headers ON (starknet_transactions.block_hash = block_headers.hash)
    ",
    )?;

    let mut rows = query_statement.query([])?;

    let mut last_block_number: u64 = 0;

    let mut total_keys: usize = 0;
    let mut total_data: usize = 0;

    let mut all_keys = HashSet::new();
    let mut all_data = HashSet::new();

    while let Some(row) = rows.next().context("Fetching next receipt")? {
        let block_number = row.get_block_number("block_number")?;

        let current_block_number = block_number.get();
        if current_block_number > last_block_number {
            if current_block_number % 100 == 0 {
                tracing::debug!(%current_block_number, "Migrating events");
            }
            last_block_number = current_block_number;
        }

        let receipt = row
            .get_ref_unwrap("receipt")
            .as_blob()
            .map_err(anyhow::Error::from)?;
        let receipt = zstd::decode_all(receipt).context("Decompressing transaction receipt")?;
        let receipt: starknet_gateway_types::reply::transaction::Receipt =
            serde_json::from_slice(&receipt).context("Deserializing transaction receipt")?;

        for event in receipt.events {
            total_keys += event.keys.len();
            for key in event.keys {
                all_keys.insert(key);
            }
            total_data += event.data.len();
            for data in event.data {
                all_data.insert(data);
            }
        }
    }

    let unique_keys = all_keys.len();
    let unique_data = all_data.len();
    tracing::info!(%total_keys, %unique_keys, %total_data, %unique_data, "Total size of keys and data");

    Ok(())
}
