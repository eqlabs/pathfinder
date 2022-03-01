use anyhow::Context;
use rusqlite::{named_params, Transaction};
use tracing::info;

use crate::{sequencer::reply::transaction, storage::schema::PostMigrationAction};

/// This schema migration moves the Starknet transactions and transaction receipts into
/// their own table. These tables are indexed by the origin Starknet block hash.
pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    // Create the new transaction and transaction receipt tables.
    transaction
        .execute(
            r"CREATE TABLE starknet_transactions (
            hash        BLOB PRIMARY KEY,
            idx         INTEGER NOT NULL,
            block_hash  BLOB NOT NULL,
            tx          BLOB,
            receipt     BLOB
        )",
            [],
        )
        .context("Create starknet transactions table")?;

    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_blocks", [], |r| r.get(0))
        .context("Count rows in starknet blocks table")?;
    if todo == 0 {
        return Ok(PostMigrationAction::None);
    }

    info!(
        "Decompressing and migrating {} blocks of transaction data, this may take a while.",
        todo
    );

    let mut stmt = transaction
        .prepare("SELECT hash, transactions, transaction_receipts FROM starknet_blocks")
        .context("Prepare statement")?;
    let mut rows = stmt.query([])?;

    let mut decompressor = zstd::bulk::Decompressor::new().context("Create zstd decompressor")?;
    let mut compressor = zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;
    const CAPACITY_100_MB: usize = 1_000 * 1_000 * 100;

    while let Some(r) = rows.next()? {
        let block_hash = r.get_ref_unwrap("hash").as_blob()?;
        let transactions = r.get_ref_unwrap("transactions").as_blob()?;
        let receipts = r.get_ref_unwrap("transaction_receipts").as_blob()?;

        let transactions = decompressor
            .decompress(transactions, CAPACITY_100_MB)
            .context("Decompressing transactions")?;
        let transactions =
            serde_json::de::from_slice::<Vec<transaction::Transaction>>(&transactions)
                .context("Deserializing transactions")?;

        let receipts = decompressor
            .decompress(receipts, CAPACITY_100_MB)
            .context("Decompressing transactions")?;
        let receipts = serde_json::de::from_slice::<Vec<transaction::Receipt>>(&receipts)
            .context("Deserializing transaction receipts")?;

        anyhow::ensure!(
            transactions.len() == receipts.len(),
            "Mismatched number of transactions and receipts"
        );

        transactions
            .into_iter()
            .zip(receipts.into_iter())
            .enumerate()
            .try_for_each(|(idx, (tx, rx))| -> anyhow::Result<_> {
                let transaction_data = serde_json::ser::to_vec(&tx).context("Serializing transaction data")?;
                let transaction_data = compressor.compress(&transaction_data).context("Compressing transaction data")?;

                let receipt_data = serde_json::ser::to_vec(&rx).context("Serializing transaction receipt data")?;
                let receipt_data = compressor.compress(&receipt_data).context("Compressing transaction receipt data")?;

                transaction.execute(r"INSERT INTO starknet_transactions ( hash,  idx,  block_hash,  tx,  receipt)
                                                                     VALUES (:hash, :idx, :block_hash, :tx, :receipt)",
        named_params![
                    ":hash": &tx.transaction_hash.0.as_be_bytes()[..],
                    ":idx": idx,
                    ":block_hash": block_hash,
                    ":tx": &transaction_data,
                    ":receipt": &receipt_data,
                ]).context("Insert transaction data into transactions table")?;

                Ok(())
            })?;
    }

    // Remove transaction columns from blocks table.
    let rows_altered = transaction
        .execute("ALTER TABLE starknet_blocks DROP COLUMN transactions", [])
        .context("Dropping transactions from starknet_blocks table")?;
    anyhow::ensure!(
        rows_altered == todo,
        "Number of altered rows did not match expectation when dropping transactions column"
    );

    let rows_altered = transaction
        .execute(
            "ALTER TABLE starknet_blocks DROP COLUMN transaction_receipts",
            [],
        )
        .context("Dropping transaction receipts from starknet_blocks table")?;
    anyhow::ensure!(
        rows_altered == todo,
        "Number of altered rows did not match expectation when dropping transaction receipts column"
    );

    // Database should be vacuum'd to defrag removal of transaction columns.
    Ok(PostMigrationAction::Vacuum)
}

#[cfg(test)]
mod tests {
    use pedersen::StarkHash;
    use rusqlite::{named_params, Connection};

    use crate::{
        core::{ContractAddress, StarknetTransactionHash, StarknetTransactionIndex},
        sequencer::reply::transaction::{
            self,
            execution_resources::{BuiltinInstanceCounter, EmptyBuiltinInstanceCounter},
            ExecutionResources,
        },
        storage::schema,
    };

    #[test]
    fn empty() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();
        schema::revision_0005::migrate(&transaction).unwrap();
    }

    #[test]
    fn stateful() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();
        schema::revision_0004::migrate(&transaction).unwrap();

        // Value doesn't have to be correct as we aren't parsing it.
        let block_hash = vec![0u8, 13u8, 25u8];
        // Create some unique transaction and receipt pairs.
        let tx_original = (0..10)
            .map(|i| transaction::Transaction {
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
                r#type: transaction::Type::InvokeFunction,
            })
            .collect::<Vec<_>>();

        let receipts_original = (0..10)
            .map(|i| transaction::Receipt {
                events: Vec::new(),
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

        let tx = serde_json::ser::to_vec(&tx_original).unwrap();
        let receipts = serde_json::ser::to_vec(&receipts_original).unwrap();

        let mut compressor = zstd::bulk::Compressor::new(10).unwrap();
        let mut decompressor = zstd::bulk::Decompressor::new().unwrap();
        let tx = compressor.compress(&tx).unwrap();
        let receipts = compressor.compress(&receipts).unwrap();

        transaction.execute(r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp,  transactions,  transaction_receipts)
                                                   VALUES (:number, :hash, :root, :timestamp, :transactions, :transaction_receipts)",
        named_params! {
                ":number": 123, // This doesn't matter
                ":hash": &block_hash,
                ":root": &vec![12u8, 33, 55],   // This doesn't matter
                ":timestamp": 200, // This doesn't matter
                ":transactions": &tx,
                ":transaction_receipts": &receipts,
            }).unwrap();

        // Perform this migration
        super::migrate(&transaction).unwrap();

        // The transactions table should now contain all the transactions and receipts.
        let mut stmt = transaction
            .prepare("SELECT * FROM starknet_transactions")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        for (i, (tx, rx)) in tx_original.iter().zip(receipts_original.iter()).enumerate() {
            let row = rows.next().unwrap().unwrap();

            let hash = row.get_ref_unwrap("hash").as_blob().unwrap();
            let hash = StarkHash::from_be_slice(hash).unwrap();
            let hash = StarknetTransactionHash(hash);

            let idx = row.get_ref_unwrap("idx").as_i64().unwrap() as usize;
            let b_hash = row.get_ref_unwrap("block_hash").as_blob().unwrap();
            let tx_i = row.get_ref_unwrap("tx").as_blob_or_null().unwrap().unwrap();
            let rx_i = row
                .get_ref_unwrap("receipt")
                .as_blob_or_null()
                .unwrap()
                .unwrap();

            let tx_i = decompressor.decompress(tx_i, 1000 * 1000).unwrap();
            let rx_i = decompressor.decompress(rx_i, 1000 * 1000).unwrap();

            let tx_i = serde_json::de::from_slice::<transaction::Transaction>(&tx_i).unwrap();
            let rx_i = serde_json::de::from_slice::<transaction::Receipt>(&rx_i).unwrap();

            assert_eq!(tx.transaction_hash, hash);
            assert_eq!(i, idx);
            assert_eq!(block_hash, b_hash);
            assert_eq!(tx, &tx_i);
            assert_eq!(rx, &rx_i);
        }
    }
}
