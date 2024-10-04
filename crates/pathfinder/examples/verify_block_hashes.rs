use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::{BlockNumber, Chain, ChainId, ReceiptCommitment};
use pathfinder_lib::state::block_hash::{
    calculate_receipt_commitment,
    verify_block_hash,
    BlockHeaderData,
    VerifyResult,
};

/// Verify block hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed block
/// hash matches values we store for the block.
///
/// Usage:
/// `cargo run --release -p pathfinder --example verify_block_hashes mainnet
/// ./mainnet.sqlite`
fn main() -> anyhow::Result<()> {
    let chain_name = std::env::args().nth(1).unwrap();
    let (chain, chain_id) = match chain_name.as_str() {
        "mainnet" => (Chain::Mainnet, ChainId::MAINNET),
        "sepolia" => (Chain::SepoliaTestnet, ChainId::SEPOLIA_TESTNET),
        "sepolia-integration" => (Chain::SepoliaIntegration, ChainId::SEPOLIA_INTEGRATION),
        _ => panic!("Expected chain name: mainnet/sepolia/sepolia-integration"),
    };

    let database_path = std::env::args().nth(2).unwrap();
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
            .context("No latest block number")?
            .0
    };

    for block_number in 0..latest_block_number.get() {
        let tx = db.transaction().unwrap();
        let block_number = BlockNumber::new_or_panic(block_number);
        let block_id = pathfinder_storage::BlockId::Number(block_number);
        let mut header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .context("Block header missing")?;
        let txn_data_for_block = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data missing")?;
        drop(tx);

        let computed_receipt_commitment = calculate_receipt_commitment(
            txn_data_for_block
                .into_iter()
                .flat_map(|(_, r, _)| Some(r))
                .collect::<Vec<_>>()
                .as_slice(),
        )?;

        // The db can be storing default values for the receipt commitment if the db was
        // created by syncing from the fgw
        if header.receipt_commitment == ReceiptCommitment::ZERO {
            header.receipt_commitment = computed_receipt_commitment;
        } else if header.receipt_commitment != computed_receipt_commitment {
            eprintln!("Receipt commitment mismatch at block number {block_number}");
        }

        let bhd = BlockHeaderData::from_header(&header);

        let result = verify_block_hash(bhd, chain, chain_id)?;

        match result {
            VerifyResult::Match => {}
            VerifyResult::Mismatch => {
                println!(
                    "Block hash mismatch at block number {block_number} hash {}",
                    header.hash
                )
            }
        }
    }

    Ok(())
}
