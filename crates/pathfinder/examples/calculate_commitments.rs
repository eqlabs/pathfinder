use std::time::Instant;

use anyhow::Context;
use pathfinder_common::StarknetBlockNumber;
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment, calculate_transaction_commitment,
};
use pathfinder_storage::{
    JournalMode, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage,
};

/// Calculate transaction and event commitments for blocks.
///
/// Usage:
/// ```
/// cargo run --release -p pathfinder --example calculate_commitments testnet.sqlite [1000] [--overwrite]
/// ```
///
fn main() -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?;
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let blocks_limit = std::env::args()
        .nth(2)
        .and_then(|limit| limit.parse::<u64>().ok())
        .unwrap_or(u64::MAX);

    let latest_block_number = {
        let tx = db.transaction().unwrap();
        StarknetBlocksTable::get_latest_number(&tx)?.unwrap()
    };
    let num_blocks = latest_block_number.get().min(blocks_limit);

    let overwrite = std::env::args()
        .last()
        .map(|flag| flag == "--overwrite")
        .unwrap_or_default();

    for block_number in 0..num_blocks {
        let tx = db.transaction().unwrap();

        let now = Instant::now();
        let block_id =
            StarknetBlocksBlockId::Number(StarknetBlockNumber::new_or_panic(block_number));
        let block = StarknetBlocksTable::get(&tx, block_id)?.unwrap();

        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&tx, block_id)?;
        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();
        let read_ms = now.elapsed().as_millis();

        let now = Instant::now();
        let (transaction_commitment, event_commitment) = (
            calculate_transaction_commitment(&transactions)?,
            calculate_event_commitment(&receipts)?,
        );
        let calc_ms = now.elapsed().as_millis();

        let now = Instant::now();
        if overwrite {
            StarknetTransactionsTable::update_block_commitments(
                &tx,
                block_id,
                transaction_commitment,
                event_commitment,
            )?;
            tx.commit().context("Commit the transaction")?;
        }
        let write_ms = now.elapsed().as_millis();

        println!(
            "\nblock: {} (tx: {}) read: {} ms, calc: {} ms, write: {} ms\ntx: {}\nev: {}",
            block.number,
            transactions.len(),
            read_ms,
            calc_ms,
            write_ms,
            transaction_commitment,
            event_commitment
        );
    }

    Ok(())
}
