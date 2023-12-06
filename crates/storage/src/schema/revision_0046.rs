use crate::params::{named_params, RowExt, ToSql};

use anyhow::Context;
use pathfinder_common::{ContractAddress, EventData, EventKey};
use pathfinder_crypto::Felt;
use rusqlite::OptionalExtension;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
CREATE TABLE starknet_events_keys (
    id INTEGER PRIMARY KEY NOT NULL,
    key BLOB UNIQUE NOT NULL
);

CREATE TABLE starknet_events_data (
    id INTEGER PRIMARY KEY NOT NULL,
    data BLOB UNIQUE NOT NULL
);

CREATE TABLE starknet_events_from_addresses (
    id INTEGER PRIMARY KEY NOT NULL,
    address BLOB UNIQUE NOT NULL
);

CREATE TABLE starknet_events_new (
    id INTEGER PRIMARY KEY NOT NULL,
    block_number  INTEGER NOT NULL,
    idx INTEGER NOT NULL,
    transaction_idx INTEGER NOT NULL,
    from_address INTEGER NOT NULL,
    keys BLOB,
    data BLOB,
    FOREIGN KEY(block_number) REFERENCES canonical_blocks(number) ON DELETE CASCADE
);
",
    )
    .context("Creating new event tables")?;

    let mut query_statement = tx.prepare(r"SELECT
        block_number,
        starknet_events.idx as idx,
        starknet_transactions.idx as transaction_idx,
        from_address,
        data,
        starknet_events.keys as keys
    FROM starknet_events
    INNER JOIN starknet_transactions ON (starknet_transactions.hash = starknet_events.transaction_hash)        
    ")?;

    let mut insert_statement = tx.prepare(
        r"INSERT INTO starknet_events_new (
        block_number,
        idx,
        transaction_idx,
        from_address,
        data,
        keys
    ) VALUES (
        :block_number,
        :idx,
        :transaction_idx,
        :from_address,
        :data,
        :keys
    )",
    )?;

    let mut rows = query_statement.query([])?;

    let mut last_block_number: u64 = 0;
    let mut keys_size: usize = 0;
    let mut data_size: usize = 0;

    while let Some(row) = rows.next().context("Fetching next event")? {
        let block_number = row.get_block_number("block_number")?;

        let current_block_number = block_number.get();
        if current_block_number > last_block_number {
            if current_block_number % 100 == 0 {
                tracing::debug!(%current_block_number, "Migrating events");
            }
            last_block_number = current_block_number;
        }

        let idx = row.get_i64("idx").map_err(anyhow::Error::from)?;
        let transaction_idx = row
            .get_i64("transaction_idx")
            .map_err(anyhow::Error::from)?;
        let from_address = row
            .get_contract_address("from_address")
            .map_err(anyhow::Error::from)?;

        let data = row
            .get_ref_unwrap("data")
            .as_blob()
            .map_err(anyhow::Error::from)?;
        let data: Vec<_> = data
            .chunks_exact(32)
            .map(|data| {
                let data = Felt::from_be_slice(data).map_err(anyhow::Error::from)?;
                Ok(EventData(data))
            })
            .collect::<Result<_, anyhow::Error>>()?;

        let keys = row
            .get_ref_unwrap("keys")
            .as_str()
            .map_err(anyhow::Error::from)?;

        // no need to allocate a vec for this in loop
        let mut temp = [0u8; 32];

        let keys: Vec<_> = keys
            .split(' ')
            .map(|key| {
                let used = base64::decode_config_slice(key, base64::STANDARD, &mut temp)
                    .map_err(anyhow::Error::from)?;
                let key = Felt::from_be_slice(&temp[..used]).map_err(anyhow::Error::from)?;
                Ok(EventKey(key))
            })
            .collect::<Result<_, anyhow::Error>>()?;

        let keys = keys
            .into_iter()
            .map(|key| intern_key(tx, &key))
            .collect::<Result<Vec<_>, _>>()?;
        let data = data
            .into_iter()
            .map(|data| intern_data(tx, &data))
            .collect::<Result<Vec<_>, _>>()?;
        let from_address = intern_from_address(tx, &from_address)?;

        const CODEC_CFG: bincode::config::Configuration = bincode::config::standard();
        let keys = bincode::encode_to_vec(keys, CODEC_CFG)?;
        let data = bincode::encode_to_vec(data, CODEC_CFG)?;

        keys_size += keys.len();
        data_size += data.len();

        insert_statement
            .execute(named_params![
                ":block_number": &block_number,
                ":idx": &idx,
                ":transaction_idx": &transaction_idx,
                ":from_address": &from_address,
                ":data": &data,
                ":keys": &keys,
            ])
            .context("Inserting event")?;
    }

    tracing::info!(%keys_size, %data_size, "Total size of keys and data");

    Ok(())
}

// fn intern_key(tx: &rusqlite::Transaction<'_>, key: &EventKey) -> anyhow::Result<i64> {
//     let mut statement = tx.prepare_cached("INSERT INTO starknet_events_keys(key) VALUES (:key) ON CONFLICT (key) DO UPDATE set id=id RETURNING id")?;
//     let id = statement
//         .query_row([key.to_sql()], |row| row.get(0))
//         .context("Inserting event key")?;

//     Ok(id)
// }

fn intern_key(tx: &rusqlite::Transaction<'_>, key: &EventKey) -> anyhow::Result<i64> {
    let mut query = tx.prepare_cached("SELECT id FROM starknet_events_keys WHERE key = :key")?;
    let id = query
        .query_row([key.to_sql()], |row| row.get(0))
        .optional()
        .context("Fetching key id")?;

    if let Some(id) = id {
        Ok(id)
    } else {
        let mut statement =
            tx.prepare_cached("INSERT INTO starknet_events_keys(key) VALUES (:key) RETURNING id")?;
        let id = statement
            .query_row([key.to_sql()], |row| row.get(0))
            .context("Inserting event key")?;

        Ok(id)
    }
}

fn intern_data(tx: &rusqlite::Transaction<'_>, key: &EventData) -> anyhow::Result<i64> {
    let mut query = tx.prepare_cached("SELECT id FROM starknet_events_data WHERE data = :data")?;
    let id = query
        .query_row([key.to_sql()], |row| row.get(0))
        .optional()
        .context("Fetching data id")?;

    if let Some(id) = id {
        Ok(id)
    } else {
        let mut statement = tx
            .prepare_cached("INSERT INTO starknet_events_data(data) VALUES (:data) RETURNING id")?;
        let id = statement
            .query_row([key.to_sql()], |row| row.get(0))
            .context("Inserting event data")?;
        Ok(id)
    }
}

fn intern_from_address(
    tx: &rusqlite::Transaction<'_>,
    address: &ContractAddress,
) -> anyhow::Result<i64> {
    let mut query = tx
        .prepare_cached("SELECT id FROM starknet_events_from_addresses WHERE address = :address")?;
    let id = query
        .query_row([address.to_sql()], |row| row.get(0))
        .optional()
        .context("Fetching from address id")?;

    if let Some(id) = id {
        Ok(id)
    } else {
        let mut statement = tx.prepare_cached(
            "INSERT INTO starknet_events_from_addresses(address) VALUES (:address) RETURNING id",
        )?;
        let id = statement
            .query_row([address.to_sql()], |row| row.get(0))
            .context("Inserting event from address")?;

        Ok(id)
    }
}
