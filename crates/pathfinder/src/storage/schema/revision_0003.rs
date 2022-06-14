use rusqlite::{params, OptionalExtension, Transaction};

use crate::storage::schema::PostMigrationAction;

/// This schema migration splits the global state table into
/// separate tables containing L1 and L2 data.
///
/// In addition, it also adds a refs table which only contains a single column.
/// This columns references the latest Starknet block for which the L1 and L2
/// states are the same.
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<PostMigrationAction> {
    // Create the new L1 table.
    transaction.execute(
        r"CREATE TABLE l1_state (
            starknet_block_number      INTEGER PRIMARY KEY,
            starknet_global_root       BLOB    NOT NULL,
            ethereum_block_hash        BLOB    NOT NULL,
            ethereum_block_number      INTEGER NOT NULL,
            ethereum_transaction_hash  BLOB    NOT NULL,
            ethereum_transaction_index INTEGER NOT NULL,
            ethereum_log_index         INTEGER NOT NULL
        )",
        [],
    )?;

    // Create the new L2 table
    transaction.execute(
        r"CREATE TABLE starknet_blocks (
            number               INTEGER PRIMARY KEY,
            hash                 BLOB    NOT NULL,
            root                 BLOB    NOT NULL,
            timestamp            INTEGER NOT NULL,
            transactions         BLOB,
            transaction_receipts BLOB
        )",
        [],
    )?;

    // Add new L1 L2 state table. This will track the latest Starknet block
    // for which L1 and L2 agree.
    transaction.execute(
        "CREATE TABLE refs (idx INTEGER PRIMARY KEY, l1_l2_head BLOB)",
        [],
    )?;

    // Migrate existing L1 data.
    transaction.execute(
        r"INSERT INTO l1_state (
            starknet_block_number,
            starknet_global_root,
            ethereum_block_hash,
            ethereum_block_number,
            ethereum_transaction_hash,
            ethereum_transaction_index,
            ethereum_log_index)

        SELECT global_state.starknet_block_number,
               global_state.starknet_global_root,
               ethereum_blocks.hash,
               ethereum_blocks.number,
               ethereum_transactions.hash,
               ethereum_transactions.idx,
               global_state.ethereum_log_index

        FROM global_state
        JOIN ethereum_transactions ON global_state.ethereum_transaction_hash = ethereum_transactions.hash
        JOIN ethereum_blocks ON ethereum_transactions.block_hash = ethereum_blocks.hash",
        [],
    )?;

    // Migrate existing L2 data. Transactions are left empty, since we
    // did not store this data yet. This does not require re-downloading
    // as these migrations only affect developer data.
    transaction.execute(
        r"INSERT INTO starknet_blocks (number, hash, root, timestamp)
        SELECT old.starknet_block_number,
               old.starknet_block_hash,
               old.starknet_global_root,
               old.starknet_block_timestamp
        FROM global_state old",
        [],
    )?;

    // Get the latest starknet block number and set the L1-L2 head reference to it.
    // This will default to null if no such number exists at all.
    //
    // This latest block is the L1-L2 head because schema 2 tracked L1 and L2 in lock-step.
    let latest: Option<u64> = transaction
        .query_row(
            r"SELECT starknet_block_number FROM global_state
        ORDER BY starknet_block_number DESC
        LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    transaction.execute(
        "INSERT INTO refs (idx, l1_l2_head) VALUES (?, ?)",
        params![1, latest],
    )?;

    // drop the old state table and ethereum tables.
    transaction.execute("DROP TABLE global_state", [])?;
    transaction.execute("DROP TABLE ethereum_transactions", [])?;
    transaction.execute("DROP TABLE ethereum_blocks", [])?;

    Ok(PostMigrationAction::None)
}

#[cfg(test)]
mod tests {
    use crate::storage::schema;
    use rusqlite::{named_params, params, Connection};

    use super::*;

    #[test]
    fn empty() {
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        schema::revision_0003::migrate(&transaction).unwrap();

        // Check that the L1_L2_head is NULL
        let mut statement = transaction
            .prepare("SELECT idx, l1_l2_head FROM refs")
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let row_id = row.get_ref_unwrap("idx").as_i64().unwrap();
        let l1_l2_head = row.get_ref_unwrap("l1_l2_head").as_i64_or_null().unwrap();
        assert_eq!(row_id, 1);
        assert_eq!(l1_l2_head, None);
    }

    #[test]
    fn stateful() {
        // Insert data into schema 2 tables, then migrate to schema 3 and
        // check that the data survived and is correct.
        let mut conn = Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        schema::revision_0001::migrate(&transaction).unwrap();
        schema::revision_0002::migrate(&transaction).unwrap();
        struct EthereumData {
            block_hash: Vec<u8>,
            block_number: u64,
            tx_hash: Vec<u8>,
            tx_index: u64,
            log_index: u64,
        }
        struct StarknetData {
            block_number: u64,
            block_hash: Vec<u8>,
            root: Vec<u8>,
            timestamp: u64,
        }

        struct Data {
            starknet: StarknetData,
            ethereum: EthereumData,
        }

        // Generate some data we can insert into schema 2 tables, and then
        // comapre against after migrating to schema 3.
        let original = (0..2)
            .map(|i| {
                let ethereum = EthereumData {
                    block_hash: vec![0x1 + i, 0x2 + i, 0x3 + i],
                    block_number: 20 + i as u64,
                    tx_hash: vec![100 + i, 101 + i, 102 + i],
                    tx_index: 33 + i as u64,
                    log_index: 50 + i as u64,
                };

                let starknet = StarknetData {
                    block_number: 66 + i as u64,
                    block_hash: vec![0x50 + i, 0x51 + i, 0x52 + i],
                    root: vec![0x60 + i, 0x61 + i, 0x62 + i],
                    timestamp: 99 + i as u64,
                };

                Data { starknet, ethereum }
            })
            .collect::<Vec<_>>();

        // Insert the data into the schema 2 tables.
        for data in &original {
            transaction
                .execute(
                    "INSERT INTO ethereum_blocks (hash, number) VALUES (?1, ?2)",
                    params![&data.ethereum.block_hash[..], data.ethereum.block_number],
                )
                .unwrap();

            transaction
                .execute(
                    "INSERT INTO ethereum_transactions (hash, idx, block_hash) VALUES (?1, ?2, ?3)",
                    params![
                        &data.ethereum.tx_hash[..],
                        data.ethereum.tx_index,
                        &data.ethereum.block_hash[..]
                    ],
                )
                .unwrap();

            transaction
            .execute(
                r"INSERT INTO global_state (
                        starknet_block_hash,
                        starknet_block_number,
                        starknet_block_timestamp,
                        starknet_global_root,
                        ethereum_transaction_hash,
                        ethereum_log_index
                    )
                    VALUES (:starknet_block_hash, :starknet_block_number, :starknet_block_timestamp,
                            :starknet_global_root, :ethereum_transaction_hash, :ethereum_log_index)",
                named_params![
                    ":starknet_block_hash": &data.starknet.block_hash[..],
                    ":starknet_block_number": data.starknet.block_number,
                    ":starknet_block_timestamp": data.starknet.timestamp,
                    ":starknet_global_root": &data.starknet.root[..],
                    ":ethereum_transaction_hash": &data.ethereum.tx_hash[..],
                    ":ethereum_log_index": data.ethereum.log_index,
                ],
            )
            .unwrap();
        }

        migrate(&transaction).unwrap();

        // Check that the data made it to schema 3 starknet_blocks table.
        let mut statement = transaction
            .prepare("SELECT * FROM starknet_blocks")
            .unwrap();
        let mut rows = statement.query([]).unwrap();

        for data in &original {
            let row = rows.next().unwrap().unwrap();

            let number = row.get_ref_unwrap("number").as_i64().unwrap() as u64;
            let hash = row.get_ref_unwrap("hash").as_blob().unwrap();
            let root = row.get_ref_unwrap("root").as_blob().unwrap();
            let timestamp = row.get_ref_unwrap("timestamp").as_i64().unwrap() as u64;
            let transactions = row
                .get_ref_unwrap("transactions")
                .as_blob_or_null()
                .unwrap();
            let transaction_receipts = row
                .get_ref_unwrap("transaction_receipts")
                .as_blob_or_null()
                .unwrap();

            assert_eq!(number, data.starknet.block_number);
            assert_eq!(hash, &data.starknet.block_hash[..]);
            assert_eq!(root, &data.starknet.root[..]);
            assert_eq!(timestamp, data.starknet.timestamp);
            assert_eq!(transactions, None);
            assert_eq!(transaction_receipts, None);
        }
        assert!(rows.next().unwrap().is_none());

        // Check that the data made it to schema 3 l1_state table.
        let mut statement = transaction.prepare("SELECT * FROM l1_state").unwrap();
        let mut rows = statement.query([]).unwrap();
        for data in &original {
            let row = rows.next().unwrap().unwrap();
            let starknet_block_number = row
                .get_ref_unwrap("starknet_block_number")
                .as_i64()
                .unwrap() as u64;
            let starknet_global_root = row
                .get_ref_unwrap("starknet_global_root")
                .as_blob()
                .unwrap();
            let ethereum_block_hash = row.get_ref_unwrap("ethereum_block_hash").as_blob().unwrap();
            let ethereum_block_number = row
                .get_ref_unwrap("ethereum_block_number")
                .as_i64()
                .unwrap() as u64;
            let ethereum_transaction_hash = row
                .get_ref_unwrap("ethereum_transaction_hash")
                .as_blob()
                .unwrap();
            let ethereum_transaction_index = row
                .get_ref_unwrap("ethereum_transaction_index")
                .as_i64()
                .unwrap() as u64;
            let ethereum_log_index =
                row.get_ref_unwrap("ethereum_log_index").as_i64().unwrap() as u64;

            assert_eq!(starknet_block_number, data.starknet.block_number);
            assert_eq!(starknet_global_root, &data.starknet.root);
            assert_eq!(ethereum_block_hash, &data.ethereum.block_hash);
            assert_eq!(ethereum_block_number, data.ethereum.block_number);
            assert_eq!(ethereum_transaction_hash, &data.ethereum.tx_hash);
            assert_eq!(ethereum_transaction_index, data.ethereum.tx_index);
            assert_eq!(ethereum_log_index, data.ethereum.log_index);
        }
        assert!(rows.next().unwrap().is_none());

        // Check the L1_L2_head
        let mut statement = transaction
            .prepare("SELECT idx, l1_l2_head FROM refs")
            .unwrap();
        let mut rows = statement.query([]).unwrap();
        let row = rows.next().unwrap().unwrap();
        let row_id = row.get_ref_unwrap("idx").as_i64().unwrap();
        let l1_l2_head = row
            .get_ref_unwrap("l1_l2_head")
            .as_i64_or_null()
            .unwrap()
            .unwrap() as u64;
        assert_eq!(row_id, 1);
        assert_eq!(l1_l2_head, original.last().unwrap().starknet.block_number);
    }
}
