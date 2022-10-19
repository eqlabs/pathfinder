#![deny(rust_2018_idioms)]

//! Load test for pathfinder JSON-RPC endpoints.
//!
//! This program expects a mainnet pathfinder node synced until block 1800,
//! since it contains references to transactions and contract addresses on mainnet.
//!
//! Running the load test:
//! ```
//! cargo run --release -p load-test -- -H http://127.0.0.1:9545 --report-file /tmp/report.html -u 30 -r 5 -t 60 --no-gzip
//! ```
use goose::prelude::*;
use rand::{Rng, SeedableRng};
use stark_hash::StarkHash;

mod requests;
mod types;

//
// Tasks
//

/// Fetch a random block, then fetch all individual transactions and receipts in the block.
async fn block_explorer(user: &mut GooseUser) -> TransactionResult {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let block_number: u64 = rng.gen_range(1..1800);

    let block = requests::get_block_by_number(user, block_number).await?;
    let block_by_hash = requests::get_block_by_hash(user, block.block_hash).await?;
    assert_eq!(block, block_by_hash);

    for (idx, hash) in block.transactions.iter().enumerate() {
        let transaction = requests::get_transaction_by_hash(user, *hash).await?;

        let transaction_by_hash_and_index =
            requests::get_transaction_by_block_hash_and_index(user, block.block_hash, idx).await?;
        assert_eq!(transaction, transaction_by_hash_and_index);

        let transaction_by_number_and_index =
            requests::get_transaction_by_block_number_and_index(user, block.block_number, idx)
                .await?;
        assert_eq!(transaction, transaction_by_number_and_index);

        let _receipt = requests::get_transaction_receipt_by_hash(user, *hash).await?;
    }

    Ok(())
}

async fn task_block_by_number(user: &mut GooseUser) -> TransactionResult {
    requests::get_block_by_number(user, 1000).await?;
    Ok(())
}

async fn task_block_by_hash(user: &mut GooseUser) -> TransactionResult {
    requests::get_block_by_hash(
        user,
        StarkHash::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
    )
    .await?;
    Ok(())
}

async fn task_block_transaction_count_by_hash(user: &mut GooseUser) -> TransactionResult {
    requests::get_block_transaction_count_by_hash(
        user,
        StarkHash::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
    )
    .await?;
    Ok(())
}

async fn task_block_transaction_count_by_number(user: &mut GooseUser) -> TransactionResult {
    requests::get_block_transaction_count_by_number(user, 1000).await?;
    Ok(())
}

async fn task_transaction_by_hash(user: &mut GooseUser) -> TransactionResult {
    requests::get_transaction_by_hash(
        user,
        StarkHash::from_hex_str(
            "0x39ee26a0251338f1ef96b66c0ffacbc7a41f36bd465055e39621673ff10fb60",
        )
        .unwrap(),
    )
    .await?;
    Ok(())
}

async fn task_transaction_by_block_number_and_index(user: &mut GooseUser) -> TransactionResult {
    requests::get_transaction_by_block_number_and_index(user, 1000, 3).await?;
    Ok(())
}

async fn task_transaction_by_block_hash_and_index(user: &mut GooseUser) -> TransactionResult {
    requests::get_transaction_by_block_hash_and_index(
        user,
        StarkHash::from_hex_str("0x58d8604f22510af5b120d1204ebf25292a79bfb09c4882c2e456abc2763d4a")
            .unwrap(),
        3,
    )
    .await?;
    Ok(())
}

async fn task_transaction_receipt_by_hash(user: &mut GooseUser) -> TransactionResult {
    requests::get_transaction_receipt_by_hash(
        user,
        StarkHash::from_hex_str(
            "0x39ee26a0251338f1ef96b66c0ffacbc7a41f36bd465055e39621673ff10fb60",
        )
        .unwrap(),
    )
    .await?;
    Ok(())
}

async fn task_block_number(user: &mut GooseUser) -> TransactionResult {
    requests::block_number(user).await?;
    Ok(())
}

async fn task_syncing(user: &mut GooseUser) -> TransactionResult {
    requests::syncing(user).await?;
    Ok(())
}

async fn task_call(user: &mut GooseUser) -> TransactionResult {
    // call a test contract deployed in block 0
    // https://voyager.online/contract/0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae
    requests::call(
        user,
        StarkHash::from_hex_str(
            "0x06ee3440b08a9c805305449ec7f7003f27e9f7e287b83610952ec36bdc5a6bae",
        )
        .unwrap(),
        &[
            // address
            "0x01e2cd4b3588e8f6f9c4e89fb0e293bf92018c96d7a93ee367d29a284223b6ff",
            // value
            "0x071d1e9d188c784a0bde95c1d508877a0d93e9102b37213d1e13f3ebc54a7751",
        ],
        // "set_value" entry point
        "0x3d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3",
        // hash of mainnet block 0
        StarkHash::from_hex_str(
            "0x47c3637b57c2b079b93c61539950c17e868a28f46cdef28f88521067f21e943",
        )
        .unwrap(),
    )
    .await?;
    Ok(())
}

async fn task_chain_id(user: &mut GooseUser) -> TransactionResult {
    requests::chain_id(user).await?;
    Ok(())
}

async fn task_get_events(user: &mut GooseUser) -> TransactionResult {
    // This returns a single event.
    let events = requests::get_events(
        user,
        requests::EventFilter {
            from_block: Some(1000),
            to_block: Some(1100),
            address: Some(
                StarkHash::from_hex_str(
                    "0x103114c4c5ac233a360d39a9217b9067be6979f3d08e1cf971fd22baf8f8713",
                )
                .unwrap(),
            ),
            keys: vec![],
            page_size: 1024,
            page_number: 0,
        },
    )
    .await?;

    assert_eq!(events.events.len(), 1);

    Ok(())
}

async fn task_get_storage_at(user: &mut GooseUser) -> TransactionResult {
    // Taken from:
    // https://alpha-mainnet.starknet.io/feeder_gateway/get_state_update?blockNumber=1700
    //
    // "block_hash": "0x58cfbc4ebe276882a28badaa9fe0fb545cba57314817e5f229c2c9cf1f7cc87"
    //
    // "storage_diffs": {"0x27a761524e94ed6d0c882e232bb4d34f12aae1b906e29c62dc682b526349056":
    // [{"key": "0x79deb98f1f7fc9a64df7073f93ce645a5f6a7588c34773ba76fdc879a2346e1",
    // "value": "0x44054cde571399c485119e55cf0b9fc7dcc151fb3486f70020d3ee4d7b20f8d"}]
    requests::get_storage_at(
        user,
        StarkHash::from_hex_str(
            "0x27a761524e94ed6d0c882e232bb4d34f12aae1b906e29c62dc682b526349056",
        )
        .unwrap(),
        StarkHash::from_hex_str(
            "0x79deb98f1f7fc9a64df7073f93ce645a5f6a7588c34773ba76fdc879a2346e1",
        )
        .unwrap(),
        StarkHash::from_hex_str(
            "0x58cfbc4ebe276882a28badaa9fe0fb545cba57314817e5f229c2c9cf1f7cc87",
        )
        .unwrap(),
    )
    .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        // primitive operations using the database
        .register_scenario(
            scenario!("block_by_number").register_transaction(transaction!(task_block_by_number)),
        )
        .register_scenario(
            scenario!("block_by_hash").register_transaction(transaction!(task_block_by_hash)),
        )
        .register_scenario(
            scenario!("block_transaction_count_by_hash")
                .register_transaction(transaction!(task_block_transaction_count_by_hash)),
        )
        .register_scenario(
            scenario!("block_transaction_count_by_number")
                .register_transaction(transaction!(task_block_transaction_count_by_number)),
        )
        .register_scenario(
            scenario!("transaction_by_hash")
                .register_transaction(transaction!(task_transaction_by_hash)),
        )
        .register_scenario(
            scenario!("transaction_by_block_number_and_index")
                .register_transaction(transaction!(task_transaction_by_block_number_and_index)),
        )
        .register_scenario(
            scenario!("transaction_by_block_hash_and_index")
                .register_transaction(transaction!(task_transaction_by_block_hash_and_index)),
        )
        .register_scenario(
            scenario!("transaction_receipt_by_hash")
                .register_transaction(transaction!(task_transaction_receipt_by_hash)),
        )
        .register_scenario(
            scenario!("block_number").register_transaction(transaction!(task_block_number)),
        )
        .register_scenario(
            scenario!("get_events").register_transaction(transaction!(task_get_events)),
        )
        .register_scenario(
            scenario!("get_storage_at").register_transaction(transaction!(task_get_storage_at)),
        )
        // primitive operations that don't use the database
        .register_scenario(scenario!("syncing").register_transaction(transaction!(task_syncing)))
        .register_scenario(scenario!("chain_id").register_transaction(transaction!(task_chain_id)))
        // primitive operation utilizing the Cairo Python subprocesses
        .register_scenario(scenario!("call").register_transaction(transaction!(task_call)))
        // composite scenario
        .register_scenario(
            scenario!("block_explorer").register_transaction(transaction!(block_explorer)),
        )
        .execute()
        .await?;

    Ok(())
}
