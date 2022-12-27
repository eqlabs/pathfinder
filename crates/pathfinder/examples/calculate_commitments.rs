use anyhow::Context;
use pathfinder_common::{StarknetBlockNumber, StarknetCommitment};
use pathfinder_lib::state::block_hash::{calculate_event_commitment, calculate_transaction_commitment};
use pathfinder_storage::{
    JournalMode, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage,
};

/// Calculate transcation and event commitments for blocks.
///
/// Usage:
/// `cargo run --release -p pathfinder --example calculate_commitments /path/to/file.sqlite`
/// 
fn main() -> anyhow::Result<()> {
    let start = std::time::Instant::now();
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

    println!("#block_num,tx_count,calc_ms,write_ms,tx_commitment,ev_commitment");

    let num_blocks = latest_block_number.get().min(blocks_limit);
    for block_number in 0..num_blocks {
        let tx = db.transaction().unwrap();
        let block_id =
            StarknetBlocksBlockId::Number(StarknetBlockNumber::new_or_panic(block_number));
        let block = StarknetBlocksTable::get(&tx, block_id)?.unwrap();
        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&tx, block_id)?;

        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();

        let now = std::time::Instant::now();
        let (transaction_commitment, event_commitment) = {
            let transaction_commitment = calculate_transaction_commitment(&transactions)?;
            let event_commitment = calculate_event_commitment(&receipts)?;
            (transaction_commitment, event_commitment)
        };
        let calc_ms = now.elapsed().as_millis() as u32;

        let now = std::time::Instant::now();
        StarknetTransactionsTable::update_block_commitments(&tx, block_id,
            StarknetCommitment(transaction_commitment),
            StarknetCommitment(event_commitment))?;
        tx.commit().context("Commit the transaction")?;
        let write_ms = now.elapsed().as_millis() as u32;

        println!(
            "{},{},{},{},{},{}",
            block.number, transactions.len(), calc_ms, write_ms, transaction_commitment, event_commitment,
        );
    }

    println!("#total: {} seconds", start.elapsed().as_secs());
    Ok(())
}
