use crate::storage::StarknetEmittedEvent;
use rusqlite::Connection;

pub fn setup_events(connection: &Connection) -> Vec<StarknetEmittedEvent> {
    use crate::storage::test_utils;

    let blocks = test_utils::create_blocks();
    let transactions_and_receipts = test_utils::create_transactions_and_receipts();

    for (i, block) in blocks.iter().enumerate() {
        connection
            .execute(
                r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp)
                                               VALUES (:number, :hash, :root, :timestamp)",
                rusqlite::named_params! {
                    ":number": block.number.0,
                    ":hash": block.hash.0.as_be_bytes(),
                    ":root": block.root.0.as_be_bytes(),
                    ":timestamp": block.timestamp.0,
                },
            )
            .unwrap();

        crate::storage::StarknetTransactionsTable::upsert(
            connection,
            block.hash,
            block.number,
            &transactions_and_receipts[i * test_utils::TRANSACTIONS_PER_BLOCK
                ..(i + 1) * test_utils::TRANSACTIONS_PER_BLOCK],
        )
        .unwrap();
    }

    test_utils::extract_events(&blocks, &transactions_and_receipts)
}
