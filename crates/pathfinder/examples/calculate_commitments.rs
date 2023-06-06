use std::time::Instant;

use anyhow::Context;
use pathfinder_common::BlockNumber;
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment, calculate_transaction_commitment,
    TransactionCommitmentFinalHashType,
};
use pathfinder_storage::{BlockId, JournalMode, StarknetBlocksTable, Storage};

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
        let block_id = BlockId::Number(BlockNumber::new_or_panic(block_number));
        let block = StarknetBlocksTable::get(&tx, block_id)?.unwrap();
        let version = StarknetBlocksTable::get_version(&tx, block_id)?;

        let transactions_and_receipts = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data for block not found")?;
        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();
        let read_ms = now.elapsed().as_millis();

        let transaction_final_hash_type =
            TransactionCommitmentFinalHashType::for_version(&version)?;
        let now = Instant::now();
        let (transaction_commitment, event_commitment) = (
            calculate_transaction_commitment(&transactions, transaction_final_hash_type)?,
            calculate_event_commitment(&receipts)?,
        );
        let calc_ms = now.elapsed().as_millis();

        let now = Instant::now();
        if overwrite {
            let sql = r"UPDATE starknet_blocks SET
            transaction_commitment = :transaction_commitment,
            event_commitment = :event_commitment
        WHERE hash = :block_hash";
            tx.execute(
                sql,
                rusqlite::named_params![
                    ":transaction_commitment": &transaction_commitment,
                    ":event_commitment": &event_commitment,
                    ":block_hash": &block.hash,
                ],
            )
            .context("Update transaction and event commitments")?;
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
