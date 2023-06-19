use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::{BlockNumber, ChainId};
use pathfinder_storage::{JournalMode, Storage};
use starknet_gateway_types::transaction_hash::{verify, VerifyResult};

/// Verify transaction hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed transaction hashes match
/// values we store for the block.
///
/// Usage:
/// `cargo run --release -p pathfinder --example verify_transaction_hashes mainnet ./mainnet.sqlite 100`
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

    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?
        .create_pool(NonZeroU32::new(1).unwrap())
        .unwrap();
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let latest_block_number = {
        let tx = db.transaction().unwrap();
        tx.block_id(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block number")?
            .context("Latest block number does not exist")?
            .0
    };

    println!("Done. Verifying transactions...");

    for block_number in start_block..latest_block_number.get() {
        if block_number % 10 == 0 {
            println!("Block: {block_number}")
        }

        let tx = db.transaction().unwrap();
        let block_id = pathfinder_storage::BlockId::Number(BlockNumber::new_or_panic(block_number));
        let transactions = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data missing")?;
        drop(tx);

        for (i, (txn, _)) in transactions.iter().enumerate() {
            match verify(txn, chain_id, BlockNumber::new_or_panic(block_number)) {
                VerifyResult::Match => {}
                VerifyResult::Mismatch(calculated) => println!(
                    "Mismatch: block {block_number} idx {i} expected {} calculated {} full_txn\n{}",
                    txn.hash(),
                    calculated,
                    serde_json::to_string(&txn).unwrap_or(">Failed to deserialize<".into())
                ),
                VerifyResult::NotVerifiable => println!(
                    "Skipped: block {block_number} idx {i} hash {} full_txn\n{}",
                    txn.hash(),
                    serde_json::to_string(&txn).unwrap_or(">Failed to deserialize<".into())
                ),
            }
        }
    }

    println!("Done.");

    Ok(())
}
