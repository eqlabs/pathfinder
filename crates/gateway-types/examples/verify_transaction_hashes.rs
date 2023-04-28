use anyhow::Context;
use pathfinder_common::{ChainId, StarknetBlockNumber};
use pathfinder_storage::{
    JournalMode, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage,
};
use starknet_gateway_types::transaction_hash::verify;

/// Verify transaction hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed transaction hashes match
/// values we store for the block.
///
/// Usage:
/// `cargo run --release -p starknet-gateway-types --example verify_transaction_hashes mainnet ./mainnet.sqlite 100`
fn main() -> anyhow::Result<()> {
    let chain_name = std::env::args().nth(1).unwrap();
    let chain_id = match chain_name.as_str() {
        "mainnet" => ChainId::MAINNET,
        "goerli" => ChainId::TESTNET,
        "testnet2" => ChainId::TESTNET2,
        "integration" => ChainId::INTEGRATION,
        _ => panic!("Expected chain name: mainnet/goerli/testnet2/integration"),
    };
    let database_path = std::env::args().nth(2).unwrap();
    let start_block = std::env::args().nth(3).unwrap_or("0".into());

    let start_block = start_block
        .parse::<u64>()
        .context("Parse start block number")?;

    println!("Migrating database...");

    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?;
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let latest_block_number = {
        let tx = db.transaction().unwrap();
        StarknetBlocksTable::get_latest_number(&tx)?.unwrap()
    };

    println!("Done. Verifying transactions...");

    for block_number in start_block..latest_block_number.get() {
        if block_number % 10 == 0 {
            println!("Block: {block_number}")
        }

        let tx = db.transaction().unwrap();
        let block_id =
            StarknetBlocksBlockId::Number(StarknetBlockNumber::new_or_panic(block_number));
        let transactions =
            StarknetTransactionsTable::get_transaction_data_for_block(&tx, block_id)?;
        drop(tx);

        for (i, (txn, _)) in transactions.iter().enumerate() {
            match verify(
                txn,
                chain_id,
                StarknetBlockNumber::new_or_panic(block_number),
            ) {
                Ok(skipped) if skipped => println!(
                    "Skipped: block {block_number} idx {i} hash {} full_txn\n{}",
                    txn.hash(),
                    serde_json::to_string(&txn).unwrap_or(">Failed to deserialize<".into())
                ),
                Ok(_) => { /* Verification passed */ }
                Err(e) => println!(
                    "{e}, block {block_number} idx {i} full_txn {}",
                    serde_json::to_string(&txn).unwrap_or(">Failed to deserialize<".into())
                ),
            }
        }
    }

    println!("Done.");

    Ok(())
}
