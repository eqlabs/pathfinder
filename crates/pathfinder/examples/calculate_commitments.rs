use std::time::Instant;

use anyhow::Context;
use pathfinder_common::BlockNumber;
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment, calculate_transaction_commitment,
    TransactionCommitmentFinalHashType,
};
use pathfinder_storage::{BlockId, JournalMode, Storage};

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
        tx.block_id(BlockId::Latest)
            .context("Fetching latest block number")?
            .context("No latest block")?
            .0
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
        let header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .context("Block header missing")?;

        let transactions_and_receipts = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data for block not found")?;
        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();
        let read_ms = now.elapsed().as_millis();

        let transaction_final_hash_type =
            TransactionCommitmentFinalHashType::for_version(&header.starknet_version)?;
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
                    ":block_hash": &header.hash,
                ],
            )
            .context("Update transaction and event commitments")?;
            tx.commit().context("Commit the transaction")?;
        }
        let write_ms = now.elapsed().as_millis();

        println!(
            "\nblock: {} (tx: {}) read: {} ms, calc: {} ms, write: {} ms\ntx: {}\nev: {}",
            header.number,
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
