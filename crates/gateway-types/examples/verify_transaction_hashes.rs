use anyhow::Context;
use pathfinder_common::{ChainId, StarknetBlockNumber};
use pathfinder_storage::{
    JournalMode, StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable, Storage,
};
use starknet_gateway_types::{
    reply::transaction::{DeclareTransaction, InvokeTransaction, Transaction},
    transaction_hash::compute_transaction_hash,
};

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
            let computed_hash = compute_transaction_hash(txn, chain_id).with_context(|| {
                format!(
                    "Compute hash for transaction: block {block_number} idx {i} hash {}",
                    txn.hash()
                )
            })?;
            if computed_hash.hash() != txn.hash() {
                println!(
                    "Mismatch: {} block {block_number} idx {i} expected {} computed {} full_txn\n{}",
                    transaction_type(txn),
                    txn.hash(),
                    computed_hash.hash(),
                    serde_json::to_string(&txn).unwrap_or("Failed to deserialize".into()),
                )
            }
        }
    }

    println!("Done.");

    Ok(())
}

fn transaction_type(txn: &Transaction) -> String {
    match txn {
        Transaction::Declare(DeclareTransaction::V0(_)) => "          Declare v0".into(),
        Transaction::Declare(DeclareTransaction::V1(_)) => "          Declare v1".into(),
        Transaction::Declare(DeclareTransaction::V2(_)) => "       Declare v2".into(),
        Transaction::Deploy(t) => format!("       Deploy v{}", t.version.0.to_low_u64_be()),
        Transaction::DeployAccount(_) => "Deploy Account v1".into(),
        Transaction::Invoke(InvokeTransaction::V0(_)) => "        Invoke v0".into(),
        Transaction::Invoke(InvokeTransaction::V1(_)) => "        Invoke v1".into(),
        Transaction::L1Handler(t) => format!("    L1 Handler v{}", t.version.0.to_low_u64_be()),
    }
}
