use std::time::Duration;

use anyhow::Context;
use pedersen::{pedersen_hash, StarkHash};
use rusqlite::{Connection, Transaction};
use web3::{Transport, Web3};

use crate::{
    core::{
        ContractHash, ContractRoot, ContractStateHash, GlobalRoot, StarknetBlockHash,
        StarknetBlockTimestamp,
    },
    ethereum::{
        log::{FetchError, StateUpdateLog},
        state_update::{
            state_root::StateRootFetcher, ContractUpdate, DeployedContract, StateUpdate,
        },
    },
    sequencer,
    state::state_tree::{ContractsStateTree, GlobalStateTree},
    storage::{
        ContractCodeTable, ContractsStateTable, ContractsTable, EthereumBlocksTable,
        EthereumTransactionsTable, GlobalStateRecord, GlobalStateTable,
    },
};

use tokio::sync::{mpsc, oneshot};

pub(crate) mod contract_hash;
mod merkle_node;
mod merkle_tree;
mod state_tree;

pub use contract_hash::compute_contract_hash;

#[derive(thiserror::Error, Debug)]
enum UpdateError {
    #[error("Ethereum chain reorg detected")]
    Reorg,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Syncs the Starknet state with L1.
pub async fn sync<T: Transport + 'static>(
    database: Connection,
    transport: Web3<T>,
    sequencer: &sequencer::Client,
) -> anyhow::Result<()> {
    // TODO: Track sync progress in some global way, so that RPC can check and react accordingly.
    //       This could either be the database, or a mutable lazy_static thingy.

    // before we start doing anything, the current database state needs to be read from the
    // database, so that we can start reading root logs
    let (initial_state_tx, initial_state_rx) = oneshot::channel();

    // root logs tell us the root hash for one thing, dunno about others; they lead to state update
    // logs for that block
    let (root_logs_tx, root_logs_rx) = mpsc::channel::<Vec<StateUpdateLog>>(1);

    // and retrieving these state updates takes a long time, so we have a separate stage for that
    let (state_update_tx, state_update_rx) = mpsc::channel::<(StateUpdateLog, StateUpdate)>(1);

    // for state updates, there are contracts which were deployed so these contract definitions
    // need to be fetched
    let (fetched_contracts_tx, fetched_contracts_rx) = mpsc::channel::<Vec<DeployedContract>>(1);

    // the fetched contract definitions need to have abi, bytecode, hash extracted and compressed
    let (compression_tx, compression_rx) = mpsc::channel::<(DeployedContract, bytes::Bytes)>(1);

    // so that they can be persisted in the database along with the other updates
    let (ready_tx, ready_contracts_rx) =
        mpsc::channel::<(DeployedContract, Result<CompressedContract, anyhow::Error>)>(1);

    // finally the simplest status display for the progress
    let (block_update_tx, mut block_update_rx) =
        mpsc::channel::<(u64, std::time::Instant, BlockInfo)>(1);

    let _jh2 = tokio::task::spawn({
        let sequencer = sequencer.clone();
        fetch_contracts(sequencer, fetched_contracts_rx, compression_tx)
    });

    let _jh = std::thread::Builder::new()
        .name(String::from("extract-compress"))
        .spawn(move || extract_compress(ready_tx, compression_rx))
        .context("failed to launch compressor thread")?;

    let _jh_db = std::thread::Builder::new()
        .name(String::from("database-updater"))
        .spawn(move || {
            update_database(
                database,
                initial_state_tx,
                state_update_rx,
                fetched_contracts_tx,
                ready_contracts_rx,
                block_update_tx,
            )
        })
        .context("failed to launch database updater thread")?;

    let _jh6 = tokio::task::spawn_local(async move {
        let mut last = None;

        // this example uses every block polling, but this could be much more useful stats
        // every 5s for example.
        while let Some((block_num, when, block_info)) = block_update_rx.recv().await {
            if let Some(last) = last {
                let elapsed = when - last;
                println!("Updated to block {block_num} in {elapsed:?}: {block_info}");
            } else {
                println!("Updated to block {block_num}: {block_info}");
            }

            last = Some(when);
        }
    });

    // needed for the web3 things
    let local = tokio::task::LocalSet::new();

    // FIXME: this could just be the sync call?
    local
        .run_until(async move {
            let _jh5 = tokio::task::spawn_local({
                let transport = transport.clone();
                retrieve_state_updates(transport, root_logs_rx, state_update_tx)
            });

            let latest_state_log = initial_state_rx.await.unwrap();
            let mut root_fetcher = StateRootFetcher::new(latest_state_log);

            loop {
                match root_fetcher.fetch(&transport).await {
                    Ok(logs) if logs.is_empty() => {}
                    Ok(logs) => {
                        root_logs_tx.send(logs).await.unwrap();
                        continue;
                    }
                    Err(FetchError::Reorg) => todo!("Handle reorg event!"),
                    Err(FetchError::Other(other)) => {
                        println!("{}", other.context("Fetching new Starknet roots from L1"));
                    }
                };

                tokio::time::sleep(Duration::from_millis(10000)).await;
            }

            // this is infinite loop, so we never leave. could have a poison message, which would
            // nicely stop all of the above created stages.
        })
        .await
}

async fn retrieve_state_updates<T: Transport + 'static>(
    transport: Web3<T>,
    mut root_logs_rx: mpsc::Receiver<Vec<StateUpdateLog>>,
    state_update_tx: mpsc::Sender<(StateUpdateLog, StateUpdate)>,
) {
    while let Some(root_logs) = root_logs_rx.recv().await {
        for root_log in root_logs {
            let state_update = StateUpdate::retrieve(&transport, root_log.clone())
                .await
                .unwrap();
            /*{
                Ok(state_update) => state_update,
                Err(RetrieveStateUpdateError::Other(other)) => {
                    return Err(anyhow::anyhow!(
                        "Fetching state update failed. {}",
                        other
                    ));
                }
                // Treat the rest as a reorg event.
                Err(_reorg) => { return Err(anyhow::anyhow!("Reorg: {:?}", _reorg)); },
            };*/

            state_update_tx
                .send((root_log, state_update))
                .await
                .expect("failed to send state updates");
        }
    }
}

async fn fetch_contracts(
    sequencer: sequencer::Client,
    mut fetched_contracts_rx: mpsc::Receiver<Vec<DeployedContract>>,
    compression_tx: mpsc::Sender<(DeployedContract, bytes::Bytes)>,
) {
    while let Some(deployed_contracts) = fetched_contracts_rx.recv().await {
        // as for the contracts to deploy, we should really check if we really need to download the
        // contract on the db thread. however we can do the default setting right away, just await for
        // the contracts in the end and deploy them then.
        for contract in deployed_contracts {
            let contract_definition = sequencer
                .full_contract(contract.address)
                .await
                .expect("Download contract definition from sequencer");

            compression_tx
                .send((contract, contract_definition))
                .await
                .unwrap();
        }
    }
}

fn update_database(
    mut database: Connection,
    initial_state_tx: oneshot::Sender<Option<StateUpdateLog>>,
    mut state_update_rx: mpsc::Receiver<(StateUpdateLog, StateUpdate)>,
    fetched_contracts_tx: mpsc::Sender<Vec<DeployedContract>>,
    mut ready_contracts_rx: mpsc::Receiver<(DeployedContract, anyhow::Result<CompressedContract>)>,
    block_update_tx: mpsc::Sender<(u64, std::time::Instant, BlockInfo)>,
) {
    let mut previous_state = {
        // Temporary transaction with no side-effects, which will rollback when
        // droppped anyway. Important not to keep this open for no reason, which might prevent
        // other writes.
        let db_tx = database.transaction().unwrap();
        GlobalStateTable::get_latest_state(&db_tx).unwrap()
    };

    let mut global_root = previous_state
        .as_ref()
        .map(|record| record.global_root)
        .unwrap_or(GlobalRoot(StarkHash::ZERO));

    let latest_state_log = previous_state.as_ref().map(StateUpdateLog::from);
    initial_state_tx.send(latest_state_log).unwrap();

    while let Some((root_log, state_update)) = state_update_rx.blocking_recv() {
        // Perform each update as an atomic database unit.
        let db_transaction = database.transaction().unwrap();

        // TODO:
        /*
        .with_context(|| {
            format!(
                "Creating database transaction for block number {}",
                root_log.block_number.0
            )
        })?;
        */

        // Verify database state integretity i.e. latest state should be sequential,
        // and we are the only writer.
        let previous_state_db = GlobalStateTable::get_latest_state(&db_transaction).unwrap();

        // TODO
        /*.with_context(|| {
                format!(
                    "Get latest StarkNet state for block number {}",
                    root_log.block_number.0
                )
            })?;
        */

        assert_eq!(
            previous_state_db, previous_state,
            "State mismatch between database and sync process for block number {}\n{:?}\n\n{:?}",
            root_log.block_number.0, previous_state, previous_state_db
        );

        let next_root = root_log.global_root;

        let block_info;

        match update(
            state_update,
            global_root,
            &root_log,
            &db_transaction,
            &fetched_contracts_tx,
            &mut ready_contracts_rx,
        ) {
            Ok(BlockUpdated { record, info }) => {
                previous_state = Some(record);
                block_info = info;
            }
            Err(UpdateError::Reorg) => todo!("Handle reorg event!"),
            Err(UpdateError::Other(other)) => {
                panic!(
                    "Updating to block number {} gave {}",
                    root_log.block_number.0, other
                );
            }
        };

        db_transaction.commit().unwrap();

        /*with_context(|| {
            format!(
                "Committing database transaction for block number {}",
                root_log.block_number.0
            )
        })?;
        */
        global_root = next_root;

        block_update_tx
            .blocking_send((
                root_log.block_number.0,
                std::time::Instant::now(),
                block_info,
            ))
            .unwrap();
    }
}

fn extract_compress(
    tx: mpsc::Sender<(DeployedContract, anyhow::Result<CompressedContract>)>,
    mut rx: mpsc::Receiver<(DeployedContract, bytes::Bytes)>,
) {
    let mut compressor = zstd::bulk::Compressor::new(10)
        .context("Couldn't create zstd compressor for ContractsTable")
        .unwrap();

    let mut process_one = |definition: bytes::Bytes| {
        // to really reuse the buffers, we should inline the extract_abi_code_hash as well.
        let (abi, bytecode, hash) =
            crate::state::contract_hash::extract_abi_code_hash(&*definition)
                .context("Compute contract hash")?;

        let abi = compressor
            .compress(&abi)
            .context("Failed to compress ABI")?;
        let bytecode = compressor
            .compress(&bytecode)
            .context("Failed to compress bytecode")?;
        let definition = compressor
            .compress(&*definition)
            .context("Failed to compress definition")?;

        Result::<_, anyhow::Error>::Ok(CompressedContract {
            abi,
            bytecode,
            definition,
            hash,
        })
    };

    while let Some((deployed_contract, def_bytes)) = rx.blocking_recv() {
        tx.blocking_send((deployed_contract, process_one(def_bytes)))
            .unwrap();
    }
}

struct CompressedContract {
    abi: Vec<u8>,
    bytecode: Vec<u8>,
    definition: Vec<u8>,
    hash: StarkHash,
}

impl std::fmt::Debug for CompressedContract {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CompressedContract {{ sizes: {:?}, hash: {} }}",
            (self.abi.len(), self.bytecode.len(), self.definition.len()),
            self.hash
        )
    }
}

/// Updates the Starknet state with a new block described by [StateUpdateLog].
///
/// Returns the new global root.
fn update(
    state_update: StateUpdate,
    global_root: GlobalRoot,
    update_log: &StateUpdateLog,
    db: &Transaction<'_>,
    fetched_contracts_tx: &mpsc::Sender<Vec<DeployedContract>>,
    ready_contracts_rx: &mut mpsc::Receiver<(DeployedContract, anyhow::Result<CompressedContract>)>,
) -> Result<BlockUpdated, UpdateError> {
    // Download update from L1.

    let contract_count = state_update.deployed_contracts.len();

    // TODO: check if the contract has been downloaded already
    fetched_contracts_tx
        .blocking_send(state_update.deployed_contracts)
        .unwrap();

    let mut global_tree =
        GlobalStateTree::load(db, global_root).context("Loading global state tree")?;

    for _ in 0..contract_count {
        let (contract, compressed) = ready_contracts_rx
            .blocking_recv()
            .context("should have gotten all of the compressed")?;

        let compressed = compressed?;

        // FIXME: this would only need to be done for contracts, which don't receive updates in this state
        // update log
        {
            let state_hash =
                calculate_contract_state_hash(contract.hash, ContractRoot(StarkHash::ZERO));

            global_tree
                .set(contract.address, state_hash)
                .context("Adding deployed contract to global state tree")?;

            // esp thinking about this being waste for most contracts which do receive updates.
            ContractsStateTable::insert(
                db,
                state_hash,
                contract.hash,
                ContractRoot(StarkHash::ZERO),
            )
            .context("Insert constract state hash into contracts state table")?;
        }

        if compressed.hash != contract.hash.0 {
            return Err(UpdateError::from(anyhow::anyhow!(
                "Contract hash mismatch on address {}: expected {}, actual {}",
                contract.address.0,
                contract.hash.0,
                compressed.hash,
            )));
        }

        ContractCodeTable::insert_compressed(
            db,
            contract.hash,
            &compressed.abi,
            &compressed.bytecode,
            &compressed.definition,
        )
        .context("Inserting contract information into contract code table")?;

        ContractsTable::insert(db, contract.address, contract.hash)
            .context("Inserting contract hash into contracts table")?;
    }

    let mut contracts_updated = 0;
    let mut total_updates = 0;

    // Update contract state tree
    for contract_update in state_update.contract_updates {
        total_updates += contract_update.storage_updates.len();

        let contract_state_hash = update_contract_state(&contract_update, &global_tree, db)
            .context("Updating contract state")?;

        // Update the global state tree.
        global_tree
            .set(contract_update.address, contract_state_hash)
            .context("Updating global state tree")?;
    }

    // Apply all global tree changes.
    let new_global_root = global_tree
        .apply()
        .context("Applying global state tree updates")?;

    // Validate calculated root against the one received from L1.
    if new_global_root != update_log.global_root {
        return Err(UpdateError::Other(anyhow::anyhow!(
            "New global state root did not match L1."
        )));
    }

    // Download additional block information from sequencer. Use a custom timeout with retry strategy
    // to work-around the sequencer's poor performance (spurious lack of response) for early blocks.
    // let block = loop {
    //     match sequencer
    //         .block_by_number_with_timeout(
    //             BlockNumberOrTag::Number(update_log.block_number),
    //             Duration::from_secs(3),
    //         )
    //         .await
    //     {
    //         Ok(block) => break block,
    //         Err(err) => {
    //             use sequencer::error::*;
    //             match err {
    //                 SequencerError::TransportError(terr) if terr.is_timeout() => continue,
    //                 other => {
    //                     let err = anyhow::anyhow!("{}", other)
    //                         .context("Downloading StarkNet block from sequencer");
    //                     return Err(UpdateError::Other(err));
    //                 }
    //             }
    //         }
    //     }
    // };

    // Verify sequencer root against L1.
    // let sequencer_root = block.state_root.context("Sequencer state root missing")?;

    // if sequencer_root != update_log.global_root {
    //     return Err(UpdateError::Other(anyhow::anyhow!(
    //         "Sequencer state root did not match L1."
    //     )));
    // }

    // let block_hash = block.block_hash.context("Sequencer block hash missing")?;
    let block_hash = StarknetBlockHash(pedersen_hash(
        update_log.global_root.0,
        StarkHash::from_be_slice(&update_log.block_number.0.to_be_bytes()).unwrap(),
    ));
    let timestamp = StarknetBlockTimestamp(0);

    // Persist new global root et al to database.
    EthereumBlocksTable::insert(
        db,
        update_log.origin.block.hash,
        update_log.origin.block.number,
    )
    .context("Updating Ethereum blocks table")?;

    EthereumTransactionsTable::insert(
        db,
        update_log.origin.block.hash,
        update_log.origin.transaction.hash,
        update_log.origin.transaction.index,
    )
    .context("Updating Ethereum transactions table")?;

    GlobalStateTable::insert(
        db,
        update_log.block_number,
        block_hash,
        timestamp,
        new_global_root,
        update_log.origin.transaction.hash,
        update_log.origin.log_index,
    )
    .context("Updating global state table")?;

    Ok(BlockUpdated {
        record: GlobalStateRecord {
            block_number: update_log.block_number,
            block_hash,
            block_timestamp: timestamp,
            global_root: new_global_root,
            eth_block_number: update_log.origin.block.number,
            eth_block_hash: update_log.origin.block.hash,
            eth_tx_hash: update_log.origin.transaction.hash,
            eth_tx_index: update_log.origin.transaction.index,
            eth_log_index: update_log.origin.log_index,
        },
        info: BlockInfo {
            deployed_contract_count: contract_count,
            updated_contracts: contracts_updated,
            total_updates,
        },
    })
}

#[derive(Debug)]
struct BlockUpdated {
    record: GlobalStateRecord,
    info: BlockInfo,
}

#[derive(Debug)]
struct BlockInfo {
    deployed_contract_count: usize,
    updated_contracts: usize,
    total_updates: usize,
}

impl std::fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} deployed contracts, {} contracts updated with total of {} updates",
            self.deployed_contract_count, self.updated_contracts, self.total_updates
        )
    }
}

/// Updates a contract's state with the given [storage updates](ContractUpdate). It returns the
/// [ContractStateHash] of the new state.
///
/// Specifically, it updates the [ContractsStateTree] and [ContractsStateTable].
fn update_contract_state(
    update: &ContractUpdate,
    global_tree: &GlobalStateTree<'_>,
    db: &Transaction<'_>,
) -> anyhow::Result<ContractStateHash> {
    // Update the contract state tree.
    let contract_state_hash = global_tree
        .get(update.address)
        .context("Get contract state hash from global state tree")?;
    let contract_root = ContractsStateTable::get_root(db, contract_state_hash)
        .context("Read contract root from contracts state table")?
        .unwrap_or(ContractRoot(StarkHash::ZERO));

    // Load the contract tree and insert the updates.
    let mut contract_tree =
        ContractsStateTree::load(db, contract_root).context("Load contract state tree")?;
    for storage_update in &update.storage_updates {
        contract_tree
            .set(storage_update.address, storage_update.value)
            .context("Update contract storage tree")?;
    }
    let new_contract_root = contract_tree
        .apply()
        .context("Apply contract storage tree changes")?;

    // Calculate contract state hash, update global state tree and persist pre-image.
    let contract_hash = ContractsTable::get_hash(db, update.address)
        .context("Read contract hash from contracts table")?
        .context("Contract hash is missing from contracts table")?;
    let contract_state_hash = calculate_contract_state_hash(contract_hash, new_contract_root);

    ContractsStateTable::insert(db, contract_state_hash, contract_hash, new_contract_root)
        .context("Insert constract state hash into contracts state table")?;

    Ok(contract_state_hash)
}

/// Calculates the contract state hash from its preimage.
fn calculate_contract_state_hash(hash: ContractHash, root: ContractRoot) -> ContractStateHash {
    const RESERVED: StarkHash = StarkHash::ZERO;
    const CONTRACT_VERSION: StarkHash = StarkHash::ZERO;

    // The contract state hash is defined as H(H(H(hash, root), RESERVED), CONTRACT_VERSION)
    let hash = pedersen_hash(hash.0, root.0);
    let hash = pedersen_hash(hash, RESERVED);
    let hash = pedersen_hash(hash, CONTRACT_VERSION);

    // Compare this with the HashChain construction used in the contract_hash: the number of
    // elements is not hashed to this hash, and this is supposed to be different.
    ContractStateHash(hash)
}

#[cfg(test)]
mod tests {
    use super::calculate_contract_state_hash;
    use crate::core::{ContractHash, ContractRoot, ContractStateHash};
    use pedersen::StarkHash;

    #[test]
    fn hash() {
        let root = StarkHash::from_hex_str(
            "04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028",
        )
        .unwrap();
        let root = ContractRoot(root);

        let hash = StarkHash::from_hex_str(
            "02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779",
        )
        .unwrap();
        let hash = ContractHash(hash);

        let expected = StarkHash::from_hex_str(
            "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3",
        )
        .unwrap();
        let expected = ContractStateHash(expected);

        let result = calculate_contract_state_hash(hash, root);

        assert_eq!(result, expected);
    }

    /*
    use crate::{
        core::{
            EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
            EthereumTransactionIndex, StarknetBlockHash, StarknetBlockNumber,
        },
        ethereum::test::create_test_transport,
    };
    use std::str::FromStr;
    use web3::types::H256;
    #[tokio::test]
    #[ignore = "Sequencer currently gives 502/503"]
    #[allow(unused, dead_code)] // broke everything
    async fn genesis() {
        // Georli genesis block values from Alpha taken from Voyager block explorer.
        // https://goerli.voyager.online/block/0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b

        let starknet_block_hash = StarknetBlockHash(
            StarkHash::from_hex_str(
                "0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b",
            )
            .unwrap(),
        );

        let genesis = StateUpdateLog {
            origin: EthOrigin {
                block: BlockOrigin {
                    hash: EthereumBlockHash(
                        H256::from_str(
                            "a3c7bb4baa81bb8bc5cc75ace7d8296b2668ccc2fd5ac9d22b5eefcfbf7f3444",
                        )
                        .unwrap(),
                    ),
                    number: EthereumBlockNumber(5854324),
                },
                transaction: TransactionOrigin {
                    hash: EthereumTransactionHash(
                        H256::from_str(
                            "97ee44ba80d1ad5cff4a5adc02311f6e19490f48ea5a57c7f510e469cae7e65b",
                        )
                        .unwrap(),
                    ),
                    index: EthereumTransactionIndex(4),
                },
                log_index: EthereumLogIndex(23),
            },
            global_root: GlobalRoot(
                StarkHash::from_hex_str(
                    "02c2bb91714f8448ed814bdac274ab6fcdbafc22d835f9e847e5bee8c2e5444e",
                )
                .unwrap(),
            ),
            block_number: StarknetBlockNumber(0),
        };

        let sequencer = sequencer::Client::goerli().unwrap();

        let storage = crate::storage::Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let transport = create_test_transport(crate::ethereum::Chain::Goerli);

        /*
        update(
            &transport,
            GlobalRoot(StarkHash::ZERO),
            &genesis,
            &transaction,
            &sequencer,
        )
        .await
        .unwrap();
        */

        // Read the new latest state from database.
        let state = GlobalStateTable::get_latest_state(&transaction)
            .unwrap()
            .unwrap();

        assert_eq!(state.block_hash, starknet_block_hash);
        assert_eq!(state.global_root, genesis.global_root);
        assert_eq!(state.block_number, genesis.block_number);
        assert_eq!(state.eth_block_hash, genesis.origin.block.hash);
        assert_eq!(state.eth_block_number, genesis.origin.block.number);
        assert_eq!(state.eth_tx_hash, genesis.origin.transaction.hash);
        assert_eq!(state.eth_tx_index, genesis.origin.transaction.index);
        assert_eq!(state.eth_log_index, genesis.origin.log_index);
    }*/

    #[tokio::test]
    async fn go_sync() {
        let database =
            crate::storage::Storage::migrate(std::path::PathBuf::from("test.sqlite")).unwrap();
        let conn = database.connection().unwrap();
        let transport =
            crate::ethereum::test::create_test_transport(crate::ethereum::Chain::Goerli);
        let sequencer = crate::sequencer::Client::goerli().unwrap();

        super::sync(conn, transport, &sequencer).await.unwrap()
    }
}
