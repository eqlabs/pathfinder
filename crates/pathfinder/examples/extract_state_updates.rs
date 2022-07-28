//! This tool can be used to extract state updates from the local `pathfinder` database.
//! Extracted state updates will be stored in a directory called
//! `extracted_state_updates_<START_BLOCK_NUMBER>_<STOP_BLOCK_NUMBER>.
//!
//! `STOP_BLOCK_NUMBER` is optional, and otherwise `latest` is assumed.
//!
//! Each state update is saved in a separate file named `<BLOCK_NUMBER>.json`
//! and contains the state diff in the same format as
//!
//! `https://alpha-mainnet.starknet.io/feeder_gateway/get_state_update?blockNumber=<BLOCK_NUMBER>`
//!
//! or
//!
//! `https://alpha4.starknet.io/feeder_gateway/get_state_update?blockNumber=<BLOCK_NUMBER>`
//!
//! depending on network type.
fn print_usage_and_exit() -> ! {
    println!(
        "USAGE: {} db_file start_block_number [end_block_number]",
        std::env::args()
            .next()
            .as_deref()
            .unwrap_or("extract_state_updates")
    );
    std::process::exit(1)
}

fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();

    let args_cnt = std::env::args().count();

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| print_usage_and_exit());

    let start = std::env::args()
        .nth(2)
        .map(|start| {
            start
                .parse::<u64>()
                .unwrap_or_else(|_| print_usage_and_exit())
        })
        .unwrap_or_else(|| print_usage_and_exit());

    let stop = std::env::args().nth(3).map(|stop| {
        stop.parse::<u64>()
            .unwrap_or_else(|_| print_usage_and_exit())
    });

    let stop = match (stop, args_cnt) {
        (Some(stop), 4) if stop >= start => Some(stop),
        (None, 3) => None,
        _ => print_usage_and_exit(),
    };

    let path = std::path::PathBuf::from(path);
    let storage = pathfinder_lib::storage::Storage::migrate(
        path.clone(),
        pathfinder_lib::storage::JournalMode::WAL,
    )
    .unwrap();

    let mut connection = storage.connection().unwrap();
    let transaction = connection.transaction().unwrap();

    let latest = pathfinder_lib::storage::StarknetBlocksTable::get_latest_number(&transaction)
        .unwrap()
        .unwrap()
        .0;

    let stop = match stop {
        Some(stop) if stop <= latest => stop,
        Some(_) => print_usage_and_exit(),
        None => latest,
    };

    let work_dir = format!("./extracted_state_updates_{start}_{stop}");

    std::fs::create_dir(&work_dir).unwrap();

    let started = std::time::Instant::now();

    extract_state_updates(&transaction, start, stop, |block_number, state_update| {
        serde_json::to_writer(
            &std::fs::File::create(format!("{work_dir}/{block_number}.json")).unwrap(),
            &state_update,
        )
        .unwrap()
    });

    tracing::info!("Processing time: {:?}", started.elapsed());
}

use bitvec::{order::Msb0, slice::BitSlice};
use pathfinder_lib::{
    core::{
        ContractAddress, ContractStateHash, GlobalRoot, StarknetBlockNumber, StorageAddress,
        StorageValue,
    },
    sequencer::reply::{
        state_update::{StateDiff, StorageDiff},
        StateUpdate,
    },
    state::{
        merkle_node::Node,
        state_tree::{ContractsStateTree, GlobalStateTree},
    },
    storage::{ContractsStateTable, StarknetBlocksBlockId, StarknetBlocksTable},
};
use rusqlite::Transaction;
use stark_hash::StarkHash;
use std::collections::HashMap;

pub fn extract_state_updates<F>(
    transaction: &Transaction<'_>,
    start_block: u64,
    end_block: u64,
    mut state_update_handler: F,
) where
    F: FnMut(u64, StateUpdate),
{
    // Contains **all** storage K-Vs up to but excluding the currently processed block, i.e.
    // the values contained describe the current state as of `(currently_processed_block - 1)`.
    let mut global_storage: HashMap<ContractAddress, HashMap<StorageAddress, StorageValue>> =
        HashMap::new();

    // If we don't start from genesis, the first iteration is used
    // to get the state diff from `0` up to `start_block - 1`, to
    // build the global storage cache.
    let (start_block, skip_first) = if start_block > 0 {
        (start_block - 1, true)
    } else {
        // Start from genesis
        (start_block, false)
    };

    // Extract storage diffs for each block, starting at genesis.
    // This is the naive way right now:
    // ```pseudocode
    //
    //     init empty global_KV_cache
    //
    //     foreach block in start_block..=end_block
    //         get all storage KVs (paths-leaves) for block
    //         if V not in global_KV_cache
    //             insert KV into block_state_diff
    //         yield block_state_diff
    //         merge block_state_diff into global_KV_cache
    // ```
    for block_number in start_block..=end_block {
        if skip_first && start_block > 0 && start_block == block_number {
            tracing::info!("Processing blocks 0-{block_number}/{end_block}");
        } else {
            tracing::info!("Processing block {block_number}/{end_block}");
        }

        // Contains all storage K-Vs for the current block that **differ** in any way from the `global_storage`
        // which is 1 block behind.
        let mut current_block_storage_delta: HashMap<
            ContractAddress,
            HashMap<StorageAddress, StorageValue>,
        > = HashMap::new();

        let block = StarknetBlocksTable::get(
            transaction,
            StarknetBlocksBlockId::Number(StarknetBlockNumber(block_number)),
        )
        .unwrap()
        .unwrap();

        let global_tree = GlobalStateTree::load(transaction, block.root).unwrap();

        // The global tree visitor will find all contract state hashes that will point us
        // to each and every contract's state
        let mut global_visitor = |node: &Node, path: &BitSlice<Msb0, u8>| match node {
            Node::Leaf(contract_state_hash) => {
                // Leaf value is the contract state hash for a particular contract address (which is the leaf path)
                // having a contract state hash we can get the contract state root
                // and traverse the entire contract state tree

                let contract_address = ContractAddress(StarkHash::from_bits(path).unwrap());
                let contract_state_root = ContractsStateTable::get_root(
                    &transaction,
                    ContractStateHash(*contract_state_hash),
                )
                .unwrap()
                .unwrap();
                let contract_state_tree =
                    ContractsStateTree::load(&transaction, contract_state_root).unwrap();

                // Any new changes to this contract's storage that occured withing this block go here
                let current_contract_delta = current_block_storage_delta
                    .entry(contract_address)
                    .or_default();

                // Storage for this contract as of `(this_block - 1)`
                let current_contract_global_storage = global_storage.entry(contract_address);

                // We use this visitor to inspect all the storage values for the current contract being processed in this very block
                let mut contract_visitor = |node: &Node, path: &BitSlice<Msb0, u8>| match node {
                    Node::Leaf(storage_value) => {
                        // Leaf value is the storage value for a particular storage key (which is the leaf path)

                        let storage_key = StorageAddress(StarkHash::from_bits(path).unwrap());
                        let storage_value = StorageValue(*storage_value);

                        match &current_contract_global_storage {
                            std::collections::hash_map::Entry::Occupied(
                                current_contract_all_diffs,
                            ) => {
                                let kvs_for_this_contract_all_diffs =
                                    current_contract_all_diffs.get();

                                match kvs_for_this_contract_all_diffs.get(&storage_key) {
                                    // This K-V pair is completely new
                                    None => {
                                        current_contract_delta.insert(storage_key, storage_value);
                                    }
                                    // Value has changed
                                    Some(old_value) if *old_value != storage_value => {
                                        current_contract_delta.insert(storage_key, storage_value);
                                    }
                                    // Value has not changed
                                    Some(_) => {
                                        // `current_contract_delta` contains an empty hash map
                                        // if there are no changes to the contract state in this entire block
                                        // in such case we will have to remove it from `current_block_storage_delta`
                                    }
                                }
                            }
                            std::collections::hash_map::Entry::Vacant(_) => {
                                // Don't check in all_storage_diffs, this entire contract is a new entry globally
                                current_contract_delta.insert(storage_key, storage_value);
                            }
                        }
                    }
                    _ => {}
                };

                contract_state_tree.dfs(&mut contract_visitor);

                // Cleanup if it turned out that there were no updates to this contract in this block
                if current_contract_delta.is_empty() {
                    current_block_storage_delta.remove(&contract_address);
                }
            }
            _ => {}
        };

        global_tree.dfs(&mut global_visitor);

        let mut state_update = StateUpdate {
            block_hash: Some(block.hash),
            new_root: block.root,
            // FIXME old_root
            old_root: GlobalRoot(StarkHash::ZERO),
            state_diff: StateDiff {
                storage_diffs: HashMap::new(),
                deployed_contracts: vec![],
                declared_contracts: vec![],
            },
        };

        // Update global storage state with the processed block
        // We cannot just
        // `global_storage.extend(current_block_storage_delta.into_iter());`
        // as existing storage K-Vs for contracts would be wiped out instead of merged
        //
        // By the way: build a "sequencer style" storage diff for this block from current_block_storage_delta
        current_block_storage_delta
            .into_iter()
            .for_each(|(contract_address, storage_updates)| {
                let storage_diffs_for_this_contract = storage_updates
                    .iter()
                    .map(|(key, value)| StorageDiff {
                        key: *key,
                        value: *value,
                    })
                    .collect::<Vec<_>>();
                state_update
                    .state_diff
                    .storage_diffs
                    .insert(contract_address, storage_diffs_for_this_contract);

                global_storage
                    .entry(contract_address)
                    .or_default()
                    .extend(storage_updates.into_iter())
            });

        if !(skip_first && block_number == start_block) {
            state_update_handler(block_number, state_update);
        }
    }
}
