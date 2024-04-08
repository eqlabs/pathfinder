use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_common::{BlockHash, BlockNumber, Chain, ChainId, StarknetVersion};
use pathfinder_crypto::Felt;
use pathfinder_lib::state::block_hash::{verify_block_hash, VerifyResult};
use starknet_gateway_types::reply::{Block, GasPrices, Status};

/// Verify block hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed block hash matches
/// values we store for the block.
///
/// Usage:
/// `cargo run --release -p pathfinder --example verify_block_hashes mainnet ./mainnet.sqlite`
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

    let mut parent_block_hash = BlockHash(Felt::ZERO);

    let latest_block_number = {
        let tx = db.transaction().unwrap();
        tx.block_id(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block number")?
            .context("No latest block number")?
            .0
    };

    for block_number in 0..latest_block_number.get() {
        let tx = db.transaction().unwrap();
        let block_id = pathfinder_storage::BlockId::Number(BlockNumber::new_or_panic(block_number));
        let header = tx
            .block_header(block_id)
            .context("Fetching block header")?
            .context("Block header missing")?;
        let transactions_and_receipts = tx
            .transaction_data_for_block(block_id)?
            .context("Transaction data missing")?;
        drop(tx);

        let block_hash = header.hash;
        let (transactions, receipts): (Vec<_>, Vec<_>) = transactions_and_receipts
            .into_iter()
            .map(|(tx, rx, ev)| (tx, (rx, ev)))
            .unzip();

        let block = Block {
            block_hash: header.hash,
            block_number: header.number,
            l1_gas_price: GasPrices {
                price_in_wei: header.eth_l1_gas_price,
                price_in_fri: header.strk_l1_gas_price,
            },
            l1_data_gas_price: GasPrices {
                price_in_wei: header.eth_l1_data_gas_price,
                price_in_fri: header.strk_l1_data_gas_price,
            },
            parent_block_hash,
            sequencer_address: Some(header.sequencer_address),
            state_commitment: header.state_commitment,
            status: Status::AcceptedOnL1,
            timestamp: header.timestamp,
            transaction_receipts: receipts,
            transactions,
            starknet_version: StarknetVersion::default(),
            l1_da_mode: Default::default(),
            transaction_commitment: header.transaction_commitment,
            event_commitment: header.event_commitment,
        };
        parent_block_hash = block_hash;

        let result = verify_block_hash(&block, chain, chain_id, block_hash)?;
        match result {
            VerifyResult::Match(_) => {}
            VerifyResult::NotVerifiable => println!(
                "Block hash cannot be verified for block number {block_number} hash {block_hash:?}"
            ),
            VerifyResult::Mismatch => {
                println!("Block hash mismatch at block number {block_number} hash {block_hash:?}")
            }
        }
    }

    Ok(())
}
