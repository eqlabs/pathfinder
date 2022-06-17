use anyhow::Context;
use pathfinder_lib::{
    core::{StarknetBlockHash, StarknetBlockNumber},
    ethereum::Chain,
    sequencer::reply::{Block, Status},
    state::block_hash::{verify_block_hash, VerifyResult},
    storage::{StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage},
};
use stark_hash::StarkHash;

/// Verify block hashes in a pathfinder database.
///
/// Iterates over all blocks in the database and verifies if the computed block hash matches
/// values we store for the block.
///
/// Usage:
/// `cargo run --release -p pathfinder --example verify_block_hashes mainnet ./mainnet.sqlite`
/// Either mainnet or goerli is accepted as the chain name.
fn main() -> anyhow::Result<()> {
    let chain_name = std::env::args().nth(1).unwrap();
    let chain = match chain_name.as_str() {
        "mainnet" => Chain::Mainnet,
        "goerli" => Chain::Goerli,
        _ => panic!("Expected chain name: mainnet/goerli"),
    };

    let database_path = std::env::args().nth(2).unwrap();
    let storage = Storage::migrate(database_path.into())?;
    let db = storage
        .connection()
        .context("Opening database connection")?;

    let mut parent_block_hash = StarknetBlockHash(StarkHash::ZERO);

    let latest_block_number = StarknetBlocksTable::get_latest_number(&db)?.unwrap();

    for block_number in 0..latest_block_number.0 {
        let block_id = StarknetBlocksBlockId::Number(StarknetBlockNumber(block_number));
        let block = StarknetBlocksTable::get(&db, block_id)?.unwrap();
        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&db, block_id)?;

        let block_hash = block.hash;
        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();

        let block = Block {
            block_hash: Some(block.hash),
            block_number: Some(block.number),
            gas_price: Some(block.gas_price),
            parent_block_hash,
            sequencer_address: Some(block.sequencer_address),
            state_root: Some(block.root),
            status: Status::AcceptedOnL1,
            timestamp: block.timestamp,
            transaction_receipts: receipts,
            transactions,
        };
        parent_block_hash = block_hash;

        let result = verify_block_hash(&block, chain, block_hash)?;
        match result {
            VerifyResult::Match => {}
            VerifyResult::NotVerifiable => println!(
                "Block hash cannot be verified for block number {} hash {:?}",
                block_number, block_hash
            ),
            VerifyResult::Mismatch => println!(
                "Block hash mismatch at block number {} hash {:?}",
                block_number, block_hash
            ),
        }
    }

    Ok(())
}
