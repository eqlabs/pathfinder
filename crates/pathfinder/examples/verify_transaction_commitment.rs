use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::BlockNumber;

/// Verify transaction hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed
/// transaction hashes match values we store for the block.
///
/// Usage:
/// `cargo run --release -p pathfinder --example verify_transaction_hashes
/// mainnet ./mainnet.sqlite 100`
fn main() -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let start_block = std::env::args().nth(2).unwrap_or("0".into());

    let start_block = start_block
        .parse::<u64>()
        .context("Parse start block number")?;

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

    println!("Verifying transaction commitments...");

    for block_number in start_block..latest_block_number.get() {
        if block_number % 10 == 0 {
            println!("Block: {block_number}")
        }

        let tx = db.transaction().unwrap();
        let block_id = pathfinder_storage::BlockId::Number(BlockNumber::new_or_panic(block_number));
        let header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .context("Block header missing")?;
        let transactions = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data missing")?;
        drop(tx);

        let transactions = transactions
            .into_iter()
            .map(|(tx, _, _)| tx)
            .collect::<Vec<_>>();
        let computed_transaction_commitment =
            pathfinder_lib::state::block_hash::calculate_transaction_commitment(
                &transactions,
                header.starknet_version,
            )?;

        if computed_transaction_commitment != header.transaction_commitment {
            println!(
                "Mismatch: block {block_number}, calculated {computed_transaction_commitment}",
            );
        }
    }

    println!("Done.");

    Ok(())
}
