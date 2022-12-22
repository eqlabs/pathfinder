use anyhow::Context;
use pathfinder_common::{Chain, StarknetBlockHash, StarknetBlockNumber};
use pathfinder_lib::state::block_hash::{
    calculate_event_commitment, calculate_transaction_commitment, verify_block_hash, VerifyResult,
};
use pathfinder_storage::{
    JournalMode, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage,
};
use stark_hash::StarkHash;
use starknet_gateway_types::reply::{Block, Status};

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
        "goerli" => Chain::Testnet,
        "integration" => Chain::Integration,
        _ => panic!("Expected chain name: mainnet/goerli/integration"),
    };

    let database_path = std::env::args().nth(2).unwrap();
    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?;
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let blocks_limit = std::env::args()
        .nth(3)
        .and_then(|limit| limit.parse::<u64>().ok())
        .unwrap_or(u64::MAX);

    let mut parent_block_hash = StarknetBlockHash(StarkHash::ZERO);

    let latest_block_number = {
        let tx = db.transaction().unwrap();
        StarknetBlocksTable::get_latest_number(&tx)?.unwrap()
    };
    println!("{}", latest_block_number.get());

    let num_blocks = latest_block_number.get().min(blocks_limit);
    for block_number in 0..num_blocks {
        let tx = db.transaction().unwrap();
        let block_id =
            StarknetBlocksBlockId::Number(StarknetBlockNumber::new_or_panic(block_number));
        let block = StarknetBlocksTable::get(&tx, block_id)?.unwrap();
        let transactions_and_receipts =
            StarknetTransactionsTable::get_transaction_data_for_block(&tx, block_id)?;
        drop(tx);

        let block_hash = block.hash;
        let (transactions, receipts): (Vec<_>, Vec<_>) =
            transactions_and_receipts.into_iter().unzip();

        let at = std::time::Instant::now();
        let (transaction_commitment, event_commitment) = {
            let transaction_commitment = calculate_transaction_commitment(&transactions)?;
            let event_commitment = calculate_event_commitment(&receipts)?;
            (transaction_commitment, event_commitment)
        };
        let ms = at.elapsed().as_millis() as u32;
        println!(
            "block: {} commitments ({} ms):\n\ttx: {}\n\tev: {}",
            block.number, ms, transaction_commitment, event_commitment
        );

        let block = Block {
            block_hash: block.hash,
            block_number: block.number,
            gas_price: Some(block.gas_price),
            parent_block_hash,
            sequencer_address: Some(block.sequencer_address),
            state_root: block.root,
            status: Status::AcceptedOnL1,
            timestamp: block.timestamp,
            transaction_receipts: receipts,
            transactions,
            starknet_version: None,
        };
        parent_block_hash = block_hash;

        let result = verify_block_hash(&block, chain, block_hash)?;
        match result {
            VerifyResult::Match(_) => {}
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
