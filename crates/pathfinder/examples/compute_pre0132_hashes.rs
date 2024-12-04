use std::io::Write;
use std::num::NonZeroU32;

use anyhow::{ensure, Context};
use pathfinder_common::{
    BlockHeader,
    BlockNumber,
    ReceiptCommitment,
    StarknetVersion,
    StateCommitment,
    StorageCommitment,
};
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment,
    calculate_receipt_commitment,
    calculate_transaction_commitment,
    compute_final_hash,
    BlockHeaderData,
};

const VERSION_CUTOFF: StarknetVersion = StarknetVersion::V_0_13_2;

/// Computes block hashes for all blocks under the 0.13.2 cutoff in 0.13.2 style
/// and stores them in a CSV file "block_hashes.csv" with the format:
/// block_number,block_hash
///
/// Usage:
/// `cargo run --release -p pathfinder --example compute_pre0132_hashes
/// /path/to/db.sqlite
fn main() -> anyhow::Result<()> {
    // Open the database
    let database_path = std::env::args().nth(1).unwrap();
    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(1).unwrap())
        .unwrap();
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    // Get latest block number
    let latest_block_number = {
        let tx = db.transaction().unwrap();
        tx.block_id(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block number")?
            .context("No latest block number")?
            .0
    };

    // Open a file where we'll save the computed hashes
    let mut csv_file = std::fs::File::create("block_hashes.csv")?;
    let mut binary_file = std::fs::File::create("block_hashes.bin")?;

    // Iterate through all pre-0.13.2 blocks
    for block_number in 0..latest_block_number.get() {
        eprint!("\rBlock {}...", block_number);

        let tx = db.transaction().unwrap();
        let block_number = BlockNumber::new_or_panic(block_number);
        let block_id = pathfinder_storage::BlockId::Number(block_number);

        // Load block header
        let mut header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .context("Block header missing")?;

        // As soon as we reach blocks in 0.13.2 we're done
        if header.starknet_version == VERSION_CUTOFF {
            println!("\rBlock {}. Done!", block_number);
            break;
        }

        // Load block tx's (to compute receipt commitment)
        let txn_data_for_block = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data missing")?;

        // Compute receipt commitment if it's not there
        if header.receipt_commitment == ReceiptCommitment::ZERO {
            header.receipt_commitment = calculate_receipt_commitment(
                txn_data_for_block
                    .clone()
                    .into_iter()
                    .flat_map(|(_, r, _)| Some(r))
                    .collect::<Vec<_>>()
                    .as_slice(),
            )?;
        }

        // Recalculate transaction commitment
        header.transaction_commitment = calculate_transaction_commitment(
            &txn_data_for_block
                .iter()
                .map(|(tx, _, _)| tx.clone())
                .collect::<Vec<_>>(),
            VERSION_CUTOFF,
        )?;

        // Recalculate event commitment
        header.event_commitment = calculate_event_commitment(
            &txn_data_for_block
                .iter()
                .map(|(tx, _, events)| (tx.hash, events.as_slice()))
                .collect::<Vec<_>>(),
            VERSION_CUTOFF,
        )?;

        // Recalculate state diff commitment
        let state_update = tx
            .state_update(block_id)?
            .context("Fetching state update")?;
        header.state_diff_commitment = state_update.compute_state_diff_commitment();

        drop(tx);

        // Ensure non-zero values for other commitments
        ensure!(
            header.state_commitment != StateCommitment::ZERO,
            "state_commitment missing"
        );
        ensure!(
            header.storage_commitment != StorageCommitment::ZERO,
            "storage_commitment missing"
        );

        // Compute the block hash in the 0.13.2 style
        let header_data = get_header_data(&header);
        let new_block_hash = compute_final_hash(&header_data);

        // Write to the CSV file
        writeln!(csv_file, "{},{}", block_number, new_block_hash)?;

        // Write to the binary file
        binary_file
            .write_all(new_block_hash.0.as_be_bytes())
            .context("Writing block hash to binary file")?;
    }

    println!("\nResults are in `block_hashes.csv` and `block_hashes.bin`");

    Ok(())
}

/// Converts from [BlockHeader] to [BlockHeaderData]
fn get_header_data(header: &BlockHeader) -> BlockHeaderData {
    BlockHeaderData {
        hash: header.hash,
        parent_hash: header.parent_hash,
        number: header.number,
        timestamp: header.timestamp,
        sequencer_address: header.sequencer_address,
        state_commitment: header.state_commitment,
        state_diff_commitment: header.state_diff_commitment,
        transaction_commitment: header.transaction_commitment,
        transaction_count: header.transaction_count as u64,
        event_commitment: header.event_commitment,
        event_count: header.event_count as u64,
        state_diff_length: header.state_diff_length,
        starknet_version: header.starknet_version,
        starknet_version_str: header.starknet_version.to_string(),
        eth_l1_gas_price: header.eth_l1_gas_price,
        strk_l1_gas_price: header.strk_l1_gas_price,
        eth_l1_data_gas_price: header.eth_l1_data_gas_price,
        strk_l1_data_gas_price: header.strk_l1_data_gas_price,
        eth_l2_gas_price: header.eth_l2_gas_price,
        strk_l2_gas_price: header.strk_l2_gas_price,
        receipt_commitment: header.receipt_commitment,
        l1_da_mode: header.l1_da_mode,
    }
}
