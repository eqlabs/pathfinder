use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::{BlockNumber, ChainId};
use rayon::prelude::*;

/// Verify transaction hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed
/// transaction hashes match values we store for the block.
///
/// Usage:
/// `cargo run --release -p pathfinder --example verify_transaction_hashes
/// mainnet ./mainnet.sqlite 100`
fn main() -> anyhow::Result<()> {
    let chain_name = std::env::args().nth(1).unwrap();
    let chain_id = match chain_name.as_str() {
        "mainnet" => ChainId::MAINNET,
        "sepolia" => ChainId::SEPOLIA_TESTNET,
        "sepolia-integration" => ChainId::SEPOLIA_INTEGRATION,
        _ => panic!("Expected chain name: mainnet/sepolia/sepolia-integration"),
    };
    let database_path = std::env::args().nth(2).unwrap();
    let start_block = std::env::args().nth(3).unwrap_or("0".into());

    let start_block = start_block
        .parse::<u64>()
        .context("Parse start block number")?;

    println!("Migrating database...");

    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
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

        transactions
            .par_iter()
            .enumerate()
            .for_each(|(i, (txn, _, _))| {
                if !txn.verify_hash(chain_id) {
                    println!("Mismatch: block {block_number} idx {i}. Full_txn\n{txn:?}",);
                }
            });
    }

    println!("Done.");

    Ok(())
}
