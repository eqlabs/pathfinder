use crate::storage::StarknetEmittedEvent;
use rusqlite::Connection;

pub const NUM_BLOCKS: usize = 4;
pub const TXNS_PER_BLOCK: usize = 10;
pub const NUM_TXNS: usize = NUM_BLOCKS * TXNS_PER_BLOCK;

pub fn setup_events(connection: &Connection) -> Vec<StarknetEmittedEvent> {
    let blocks = crate::storage::test_utils::create_blocks::<NUM_BLOCKS>();
    let transactions_and_receipts =
        crate::storage::test_utils::create_transactions_and_receipts::<NUM_TXNS>();

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
            &transactions_and_receipts[i * TXNS_PER_BLOCK..(i + 1) * TXNS_PER_BLOCK],
        )
        .unwrap();
    }

    transactions_and_receipts
        .iter()
        .enumerate()
        .map(|(i, (txn, receipt))| {
            let event = &receipt.events[0];
            let block = &blocks[i / 10];

            StarknetEmittedEvent {
                data: event.data.clone(),
                from_address: event.from_address,
                keys: event.keys.clone(),
                block_hash: block.hash,
                block_number: block.number,
                transaction_hash: txn.transaction_hash,
            }
        })
        .collect()
}
