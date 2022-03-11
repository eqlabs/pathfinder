use anyhow::Context;
use rusqlite::{named_params, Transaction};

use crate::sequencer::reply::transaction;
use crate::storage::schema::PostMigrationAction;

pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    // Create the new events table.
    transaction
        .execute_batch(
            r"CREATE TABLE starknet_events (
                block_number  INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                transaction_hash BLOB NOT NULL,
                from_address BLOB NOT NULL,
                -- Keys are represented as base64 encoded strings separated by space
                keys TEXT,
                data BLOB,
                FOREIGN KEY(block_number) REFERENCES starknet_blocks(number)
            );

            CREATE VIRTUAL TABLE starknet_events_keys
            USING fts5(
                keys,
                content='starknet_events',
                content_rowid='rowid',
                tokenize='ascii'
            );

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
        .context("Create starknet events tables and indexes")?;

    // Create an index on starknet_blocks(hash) so that we can look up block numbers based
    // on block hashes quicker.
    transaction
        .execute(
            r"CREATE INDEX starknet_blocks_hash ON starknet_blocks(hash)",
            [],
        )
        .context("Create block hash index")?;

    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_transactions", [], |r| {
            r.get(0)
        })
        .context("Count rows in starknet transactions table")?;

    tracing::info!(
        num_transactions=%todo,
        "Decompressing and migrating events, this may take a while.",
    );

    let mut stmt = transaction
        .prepare("SELECT hash, block_hash, tx, receipt FROM starknet_transactions")
        .context("Prepare transaction query")?;
    let mut rows = stmt.query([])?;

    let mut decompressor = zstd::bulk::Decompressor::new().context("Create zstd decompressor")?;
    const CAPACITY_100_MB: usize = 1_000 * 1_000 * 100;

    while let Some(r) = rows.next()? {
        let transaction_hash = r.get_ref_unwrap("hash").as_blob()?;
        let block_hash = r.get_ref_unwrap("block_hash").as_blob()?;
        let tx = r.get_ref_unwrap("tx").as_blob()?;
        let receipt = r.get_ref_unwrap("receipt").as_blob()?;

        let tx = decompressor
            .decompress(tx, CAPACITY_100_MB)
            .context("Decompress transaction")?;
        let tx: transaction::Transaction =
            serde_json::de::from_slice(&tx).context("Deserializing transaction")?;
        let receipt = decompressor
            .decompress(receipt, CAPACITY_100_MB)
            .context("Decompress receipt")?;
        let receipt: transaction::Receipt =
            serde_json::de::from_slice(&receipt).context("Deserializing transaction receipt")?;

        receipt.events.into_iter().enumerate().try_for_each(
            |(idx, event)| -> anyhow::Result<_> {
                let block_number: u64 = transaction.query_row("SELECT number FROM starknet_blocks WHERE hash=:block_hash",
                    named_params![
                        ":block_hash": block_hash,
                    ],
                    |row| row.get(0)
                ).context("Query block number based on block hash")?;

                // TODO: extract
                let serialized_data: Vec<u8> = event.data.iter().flat_map(|e| {e.0.as_be_bytes().clone().into_iter()}).collect();

                // TODO: extract
                // TODO: we really should be using Iterator::intersperse() here once it's stabilized.
                let serialized_keys: Vec<String> = event.keys.iter().map(|key| base64::encode(key.0.as_be_bytes())).collect();
                let serialized_keys = serialized_keys.join(" ");

                transaction.execute(r"INSERT INTO starknet_events ( block_number,  idx,  transaction_hash,  from_address,  keys,  data)
                                                           VALUES (:block_number, :idx, :transaction_hash, :from_address, :keys, :data)",
                    named_params![
                        ":block_number": block_number,
                        ":idx": idx,
                        ":transaction_hash": transaction_hash,
                        ":from_address": &tx.contract_address.0.as_be_bytes()[..],
                        ":keys": &serialized_keys,
                        ":data": &serialized_data,
                    ]
                ).context("Insert event data into events table")?;

                Ok(())
            },
        )?;
    }

    Ok(PostMigrationAction::None)
}

#[cfg(test)]
mod tests {
    use pedersen::StarkHash;
    use rusqlite::Connection;

    use crate::{
        core::{
            ContractAddress, EventData, EventKey, StarknetTransactionHash, StarknetTransactionIndex,
        },
        sequencer::reply::transaction::{
            self as starknet_transaction,
            execution_resources::{BuiltinInstanceCounter, EmptyBuiltinInstanceCounter},
            ExecutionResources,
        },
        storage::schema,
    };

    use super::*;

    #[test]
    fn empty() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();
        schema::revision_0006::migrate(&transaction).unwrap();

        let action = super::migrate(&transaction).unwrap();
        assert_eq!(action, PostMigrationAction::None);
    }

    #[test]
    fn stateful() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();
        schema::revision_0006::migrate(&transaction).unwrap();

        // Value doesn't have to be correct as we aren't parsing it.
        let block_hash = vec![0u8, 13u8, 25u8];
        const BLOCK_NUMBER: i64 = 123;

        transaction
            .execute(
                r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp)
                                       VALUES (:number, :hash, :root, :timestamp)",
                named_params![
                    ":number": BLOCK_NUMBER,
                    ":hash": &block_hash,
                    ":root": &vec![12u8, 33, 55], // Value doesn't matter
                    ":timestamp": 200, // Value doesn't matter
                ],
            )
            .unwrap();

        // Create some unique transaction and receipt pairs.
        let tx_original = (0..10)
            .map(|i| starknet_transaction::Transaction {
                calldata: None,
                constructor_calldata: None,
                contract_address: ContractAddress(
                    StarkHash::from_hex_str(&"23".repeat(i as usize + 3)).unwrap(),
                ),
                contract_address_salt: None,
                entry_point_type: None,
                entry_point_selector: None,
                signature: None,
                transaction_hash: StarknetTransactionHash(
                    StarkHash::from_hex_str(&"fe".repeat(i as usize + 3)).unwrap(),
                ),
                r#type: starknet_transaction::Type::InvokeFunction,
                max_fee: None,
            })
            .collect::<Vec<_>>();

        let receipts_original = (0..10)
            .map(|i| starknet_transaction::Receipt {
                events: vec![starknet_transaction::Event {
                    from_address: ContractAddress(
                        StarkHash::from_hex_str(&"23".repeat(i as usize + 3)).unwrap(),
                    ),
                    data: vec![EventData(
                        StarkHash::from_hex_str(&"ce".repeat(i as usize + 3)).unwrap(),
                    )],
                    keys: vec![EventKey(
                        StarkHash::from_hex_str(&"cc".repeat(i as usize + 3)).unwrap(),
                    )],
                }],
                execution_resources: ExecutionResources {
                    builtin_instance_counter: BuiltinInstanceCounter::Empty(
                        EmptyBuiltinInstanceCounter {},
                    ),
                    n_steps: i + 987,
                    n_memory_holes: i + 1177,
                },
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: Vec::new(),
                transaction_hash: StarknetTransactionHash(
                    StarkHash::from_hex_str(&"ee".repeat(i as usize + 3)).unwrap(),
                ),
                transaction_index: StarknetTransactionIndex(i + 2311),
            })
            .collect::<Vec<_>>();

        let mut compressor = zstd::bulk::Compressor::new(1)
            .context("Create zstd compressor")
            .unwrap();

        tx_original
            .iter()
            .zip(receipts_original.iter())
            .enumerate()
            .for_each(|(idx, (tx, receipt))| {
                let transaction_data = serde_json::ser::to_vec(tx).unwrap();
                let transaction_data = compressor.compress(&transaction_data).unwrap();

                let receipt_data = serde_json::ser::to_vec(receipt).unwrap();
                let receipt_data = compressor.compress(&receipt_data).unwrap();

                transaction.execute(r"INSERT INTO starknet_transactions ( hash,  idx,  block_hash,  tx,  receipt)
                                                                 VALUES (:hash, :idx, :block_hash, :tx, :receipt)",
                    named_params![
                        ":hash": &tx.transaction_hash.0.as_be_bytes()[..],
                        ":idx": idx,
                        ":block_hash": block_hash,
                        ":tx": &transaction_data,
                        ":receipt": &receipt_data,
                    ]).unwrap();
            });

        let action = super::migrate(&transaction).unwrap();
        assert_eq!(action, PostMigrationAction::None);

        let mut stmt = transaction
            .prepare("SELECT * FROM starknet_events")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        for (tx, receipt) in tx_original.iter().zip(receipts_original.iter()) {
            for (event_idx, event) in receipt.events.iter().enumerate() {
                let row = rows.next().unwrap().unwrap();

                let block_number = row.get_ref_unwrap("block_number").as_i64().unwrap();
                let idx = row.get_ref_unwrap("idx").as_i64().unwrap() as usize;

                let transaction_hash = row.get_ref_unwrap("transaction_hash").as_blob().unwrap();
                let transaction_hash = StarkHash::from_be_slice(transaction_hash).unwrap();
                let transaction_hash = StarknetTransactionHash(transaction_hash);

                let from_address = row.get_ref_unwrap("from_address").as_blob().unwrap();
                let from_address = StarkHash::from_be_slice(from_address).unwrap();
                let from_address = ContractAddress(from_address);

                let data = row.get_ref_unwrap("data").as_blob().unwrap();
                let data: Vec<EventData> = data
                    .chunks_exact(32)
                    .map(|event_data| {
                        let event_data = StarkHash::from_be_slice(event_data).unwrap();
                        EventData(event_data)
                    })
                    .collect();

                let keys = row.get_ref_unwrap("keys").as_str().unwrap();
                let keys: Vec<EventKey> = keys
                    .split(' ')
                    .map(|v| {
                        EventKey(StarkHash::from_be_slice(&base64::decode(v).unwrap()).unwrap())
                    })
                    .collect();

                assert_eq!(BLOCK_NUMBER, block_number);
                assert_eq!(event_idx, idx);
                assert_eq!(tx.transaction_hash, transaction_hash);
                assert_eq!(tx.contract_address, from_address);
                assert_eq!(event.data, data);
                assert_eq!(event.keys, keys);
            }
        }
    }
}
