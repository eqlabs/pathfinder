#![deny(rust_2018_idioms)]

//! Load test for pathfinder JSON-RPC endpoints.
//!
//! This program expects a mainnet pathfinder node synced until block 1800,
//! since it contains references to transactions and contract addresses on
//! mainnet.
//!
//! Running the load test:
//! ```
//! cargo run --release -- -H http://127.0.0.1:9545 --report-file /tmp/report.html -u 30 -r 5 -t 60 --no-gzip
//! ```
use goose::prelude::*;

mod requests;
mod tasks;
mod types;

fn register_v05(attack: GooseAttack) -> GooseAttack {
    use tasks::scripted::{mainnet_scripted, mainnet_scripted_without_huge_calls};
    use tasks::v05::*;

    attack
        // primitive operations using the database
        .register_scenario(
            scenario!("v05_block_by_number")
                .register_transaction(transaction!(task_block_by_number)),
        )
        .register_scenario(
            scenario!("v05_block_by_hash").register_transaction(transaction!(task_block_by_hash)),
        )
        .register_scenario(
            scenario!("v05_state_update_by_hash")
                .register_transaction(transaction!(task_state_update_by_hash)),
        )
        .register_scenario(
            scenario!("v05_get_class").register_transaction(transaction!(task_class_by_hash)),
        )
        .register_scenario(
            scenario!("v05_get_class_hash_at")
                .register_transaction(transaction!(task_class_hash_at)),
        )
        .register_scenario(
            scenario!("v05_get_class_at").register_transaction(transaction!(task_class_at)),
        )
        .register_scenario(
            scenario!("v05_block_transaction_count_by_hash")
                .register_transaction(transaction!(task_block_transaction_count_by_hash)),
        )
        .register_scenario(
            scenario!("v05_block_transaction_count_by_number")
                .register_transaction(transaction!(task_block_transaction_count_by_number)),
        )
        .register_scenario(
            scenario!("v05_transaction_by_hash")
                .register_transaction(transaction!(task_transaction_by_hash)),
        )
        .register_scenario(
            scenario!("v05_transaction_by_block_number_and_index")
                .register_transaction(transaction!(task_transaction_by_block_number_and_index)),
        )
        .register_scenario(
            scenario!("v05_transaction_by_block_hash_and_index")
                .register_transaction(transaction!(task_transaction_by_block_hash_and_index)),
        )
        .register_scenario(
            scenario!("v05_transaction_receipt_by_hash")
                .register_transaction(transaction!(task_transaction_receipt_by_hash)),
        )
        .register_scenario(
            scenario!("v05_block_number").register_transaction(transaction!(task_block_number)),
        )
        .register_scenario(
            scenario!("v05_get_events").register_transaction(transaction!(task_get_events)),
        )
        .register_scenario(
            scenario!("v05_get_storage_at").register_transaction(transaction!(task_get_storage_at)),
        )
        .register_scenario(
            scenario!("v05_get_nonce").register_transaction(transaction!(task_get_nonce)),
        )
        // primitive operations that don't use the database
        .register_scenario(
            scenario!("v05_syncing").register_transaction(transaction!(task_syncing)),
        )
        .register_scenario(
            scenario!("v05_chain_id").register_transaction(transaction!(task_chain_id)),
        )
        // primitive operation doing execution
        .register_scenario(scenario!("v05_call").register_transaction(transaction!(task_call)))
        .register_scenario(
            scenario!("v05_estimate_fee").register_transaction(transaction!(task_estimate_fee)),
        )
        // composite scenario
        .register_scenario(
            scenario!("v05_block_explorer").register_transaction(transaction!(block_explorer)),
        )
        // scripted scenarios
        .register_scenario(
            scenario!("v06_scripted_mainnet").register_transaction(transaction!(mainnet_scripted)),
        )
        .register_scenario(
            scenario!("v06_scripted_mainnet_without_huge_calls")
                .register_transaction(transaction!(mainnet_scripted_without_huge_calls)),
        )
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    let attack = GooseAttack::initialize()?;
    let attack = register_v05(attack);

    attack.execute().await?;

    Ok(())
}
