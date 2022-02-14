use std::{collections::HashMap, time::Duration};

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

/// Syncs the Starknet state with L1.
pub async fn sync<T: Transport + 'static>(
    database: Connection,
    transport: Web3<T>,
    sequencer: &sequencer::Client,
) -> anyhow::Result<()> {
    // TODO: Track sync progress in some global way, so that RPC can check and react accordingly.
    //       This could either be the database, or a mutable lazy_static thingy.

    // what follows is a simple staging + communication through channels implementation. it does
    // give us:
    //
    // - database operations done outside of async contexts
    // - some testability for the database update operation
    //
    // it should not be considered as the final form, as there's too many things going on for this
    // to bring any clarity.

    // before we start doing anything, the current database state needs to be read from the
    // database, so that we can start reading root logs
    let (initial_state_tx, initial_state_rx) = oneshot::channel();

    // root logs tell us the root hash for one thing, dunno about others; they lead to state update
    // logs for that block
    let (root_logs_tx, root_logs_rx) = mpsc::channel::<Vec<StateUpdateLog>>(1);

    // and retrieving these state updates takes a long time, so we have a separate stage for that
    let (state_update_tx, state_update_rx) = mpsc::channel::<(StateUpdateLog, StateUpdate)>(1);

    // for state updates, there are contracts which were deployed so these contract definitions
    // need to be fetched.
    //
    // It is important that these vec entries are processed in fifo order, as
    // the final step expects to receive the values in the same order as they were sent.
    let (fetched_contracts_tx, fetched_contracts_rx) =
        mpsc::channel::<Vec<FetchExtractContract>>(1);

    // the fetched contract definitions need to have abi, bytecode, hash extracted and compressed
    let (compression_tx, compression_rx) = mpsc::channel::<FetchedExtractableContract>(1);

    // so that they can be persisted in the database along with the other updates
    let (ready_tx, ready_contracts_rx) = mpsc::channel::<FetchedCompressedContract>(1);

    // finally the simplest status display for the progress
    let (block_update_tx, mut block_update_rx) =
        mpsc::channel::<(u64, std::time::Instant, BlockInfo)>(1);

    // all of the join handles below are gathered for awaiting them, except for the threads.

    let fetch_contracts = tokio::task::spawn({
        let sequencer = sequencer.clone();
        fetch_contracts(sequencer, fetched_contracts_rx, compression_tx)
    });

    let extract_compress = std::thread::Builder::new()
        .name(String::from("extract-compress"))
        // assuming this is too simple to panic
        .spawn(move || extract_compress(ready_tx, compression_rx).unwrap())
        .context("failed to launch compressor thread")?;

    // tx dropped before sending => panic
    let (db_ended_tx, mut db_ended_rx) = oneshot::channel();
    let _jh_db = std::thread::Builder::new()
        .name(String::from("database-updater"))
        .spawn(move || {
            let res = update_database(
                database,
                initial_state_tx,
                state_update_rx,
                fetched_contracts_tx,
                ready_contracts_rx,
                block_update_tx,
            );
            println!("database updater exited with {:?}", res);
            // we can't really handle the failure here in at any capacity
            let _ = db_ended_tx.send(());
        })
        .context("failed to launch database updater thread")?;

    let progress_reporter = tokio::task::spawn(async move {
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

    local
        .run_until(async move {
            let root_fetcher = tokio::task::spawn_local({
                let transport = transport.clone();

                async move {
                    let latest_state_log = initial_state_rx.await.unwrap();
                    let mut root_fetcher = StateRootFetcher::new(latest_state_log);

                    loop {
                        match root_fetcher.fetch(&transport).await {
                            Ok(logs) if logs.is_empty() => {}
                            Ok(logs) => {
                                if root_logs_tx.send(logs).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                            Err(FetchError::Reorg) => todo!("Handle reorg event!"),
                            Err(FetchError::Other(other)) => {
                                println!(
                                    "{}",
                                    other.context("Fetching new Starknet roots from L1")
                                );
                            }
                        };

                        tokio::time::sleep(Duration::from_millis(10000)).await;
                    }
                }
            });

            let state_updates = tokio::task::spawn_local({
                let transport = transport.clone();
                async move {
                    retrieve_state_updates(transport, root_logs_rx, state_update_tx)
                        .await
                        .context("retrieving state updates ended in error")
                        .unwrap()
                }
            });

            // this might be a bit overboard, or the minimal implementation, but it should catch
            // all of the threads and tasks joining in.

            use futures::stream::StreamExt;

            let mut joinhandles = futures::stream::FuturesUnordered::new();
            joinhandles.push(state_updates);
            joinhandles.push(root_fetcher);
            joinhandles.push(progress_reporter);
            joinhandles.push(fetch_contracts);

            let mut updater_exited = false;

            while !joinhandles.is_empty() && !updater_exited {
                tokio::select! {
                    Some(joined) = joinhandles.next(), if !joinhandles.is_empty() => {
                        match joined {
                            Ok(_) => {},
                            Err(e) => println!("{:?}", e),
                        }
                    },
                    exit = (&mut db_ended_rx), if !updater_exited => {
                        updater_exited = true;
                        if exit.is_err() {
                            println!("database updater panicked");
                        }
                    },
                };
            }

            let database_updater_res = _jh_db.join();
            let extract_compress_res = extract_compress.join();

            println!(
                "threads joined, db: {:?}, extract_compress: {:?}",
                database_updater_res, extract_compress_res
            );

            todo!("panicked somewhere");

            // this is infinite loop, so we never leave. could have a poison message, which would
            // nicely stop all of the above created stages.
        })
        .await
}

async fn retrieve_state_updates<T: Transport + 'static>(
    transport: Web3<T>,
    mut root_logs_rx: mpsc::Receiver<Vec<StateUpdateLog>>,
    state_update_tx: mpsc::Sender<(StateUpdateLog, StateUpdate)>,
) -> anyhow::Result<()> {
    while let Some(root_logs) = root_logs_rx.recv().await {
        for root_log in root_logs {
            let state_update = StateUpdate::retrieve(&transport, root_log.clone())
                .await
                .context("Fetching state update failed")?;

            // FIXME: we must handle the reorg

            if state_update_tx
                .send((root_log, state_update))
                .await
                .is_err()
            {
                // TODO: this has a workaround over loooong debug; but it doesn't make any sense to
                // get rid of the automatically generated one, maybe this will be handled by a
                // message type down the line.
                //
                // Also noting that failure to send to the channel is regarded now only as a
                // shutdown message.
                break;
            }
        }
    }

    Ok(())
}

async fn fetch_contracts(
    sequencer: sequencer::Client,
    mut fetched_contracts_rx: mpsc::Receiver<Vec<FetchExtractContract>>,
    compression_tx: mpsc::Sender<FetchedExtractableContract>,
) {
    while let Some(cmds) = fetched_contracts_rx.recv().await {
        // as for the contracts to deploy, we should really check if we really need to download the
        // contract on the db thread. however we can do the default setting right away, just await for
        // the contracts in the end and deploy them then.
        for FetchExtractContract(address) in cmds {
            let contract_definition = sequencer
                .full_contract(address)
                .await
                .expect("Download contract definition from sequencer");

            let response = FetchedExtractableContract(address, contract_definition);

            if compression_tx.send(response).await.is_err() {
                // just exit cleanly, someone else exited already
                break;
            }
        }
    }
}

fn update_database(
    mut database: Connection,
    initial_state_tx: oneshot::Sender<Option<StateUpdateLog>>,
    mut state_update_rx: mpsc::Receiver<(StateUpdateLog, StateUpdate)>,
    fetched_contracts_tx: mpsc::Sender<Vec<FetchExtractContract>>,
    mut ready_contracts_rx: mpsc::Receiver<FetchedCompressedContract>,
    block_update_tx: mpsc::Sender<(u64, std::time::Instant, BlockInfo)>,
) -> anyhow::Result<()> {
    let mut previous_state = {
        // Temporary transaction with no side-effects, which will rollback when
        // droppped anyway. Important not to keep this open for no reason, which might prevent
        // other writes.
        let db_tx = database.transaction()?;
        GlobalStateTable::get_latest_state(&db_tx)?
    };

    let mut global_root = previous_state
        .as_ref()
        .map(|record| record.global_root)
        .unwrap_or(GlobalRoot(StarkHash::ZERO));

    let latest_state_log = previous_state.as_ref().map(StateUpdateLog::from);
    if initial_state_tx.send(latest_state_log).is_err() {
        return Ok(());
    }

    while let Some((root_log, state_update)) = state_update_rx.blocking_recv() {
        // Perform each update as an atomic database unit.
        let db_transaction = database.transaction().with_context(|| {
            format!(
                "Creating database transaction for block number {}",
                root_log.block_number.0
            )
        })?;

        // Verify database state integretity i.e. latest state should be sequential,
        // and we are the only writer.
        let previous_state_db =
            GlobalStateTable::get_latest_state(&db_transaction).with_context(|| {
                format!(
                    "Get latest StarkNet state for block number {}",
                    root_log.block_number.0
                )
            })?;

        anyhow::ensure!(
            previous_state_db == previous_state,
            "State mismatch between database and sync process for block number {}\n{:?}\n\n{:?}",
            root_log.block_number.0,
            previous_state,
            previous_state_db
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
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Updating to block number {} gave {:?}",
                    root_log.block_number.0,
                    e
                ));
            }
        };

        db_transaction.commit().with_context(|| {
            format!(
                "Committing database transaction for block number {}",
                root_log.block_number.0
            )
        })?;

        global_root = next_root;

        let progress = (
            root_log.block_number.0,
            std::time::Instant::now(),
            block_info,
        );

        if block_update_tx.blocking_send(progress).is_err() {
            break;
        }
    }

    Ok(())
}

fn extract_compress(
    tx: mpsc::Sender<FetchedCompressedContract>,
    mut rx: mpsc::Receiver<FetchedExtractableContract>,
) -> anyhow::Result<()> {
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

    while let Some(FetchedExtractableContract(address, payload)) = rx.blocking_recv() {
        let resp = FetchedCompressedContract(address, process_one(payload)?);
        if tx.blocking_send(resp).is_err() {
            break;
        }
    }

    Ok(())
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

/// Command sent from database update thread to the async contract fetcher.
#[derive(Debug, PartialEq)]
struct FetchExtractContract(crate::core::ContractAddress);

/// Intermediate fetched, but not yet extracted and compressed contract definition.
#[derive(Debug)]
struct FetchedExtractableContract(crate::core::ContractAddress, bytes::Bytes);

#[derive(Debug)]
struct FetchedCompressedContract(crate::core::ContractAddress, CompressedContract);

/// Updates the Starknet state with a new block described by [StateUpdateLog].
///
/// Returns the new global root.
fn update(
    state_update: StateUpdate,
    // FIXME: rename as "from_root" as there's the new in update_log
    global_root: GlobalRoot,
    update_log: &StateUpdateLog,
    db: &Transaction<'_>,
    fetched_contracts_tx: &mpsc::Sender<Vec<FetchExtractContract>>,
    ready_contracts_rx: &mut mpsc::Receiver<FetchedCompressedContract>,
) -> anyhow::Result<BlockUpdated> {
    let tree_updates = combine_to_tree_updates(
        db,
        state_update.deployed_contracts,
        state_update.contract_updates,
    )
    .context("Prepare tree updates")?;

    let fetch_commands = tree_updates
        .iter()
        .filter_map(TreeUpdate::as_fetch_command)
        .collect::<Vec<_>>();

    let fetch_command_count = fetch_commands.len();
    fetched_contracts_tx.blocking_send(fetch_commands).unwrap();

    let mut global_tree =
        GlobalStateTree::load(db, global_root).context("Loading global state tree")?;

    let mut updated_contracts = 0;
    let mut total_updates = 0;
    let mut deployed_contract_count = 0;
    let mut awaited = 0;

    let mut await_time = std::time::Duration::ZERO;

    for tree_update in tree_updates {
        use TreeUpdate::*;

        let (address, update, deploy, fetched) = match tree_update {
            Update(u) => {
                let u = u.unwrap();
                (u.address, Some(u), None, false)
            }
            Deploy(d, fetched) => (d.address, None, Some(d), fetched.implies_fetch()),
            UpdateDeploy(u, d, fetched) => (u.address, Some(u), Some(d), fetched.implies_fetch()),
        };

        if fetched {
            let started_at = std::time::Instant::now();
            let FetchedCompressedContract(fetched_address, payload) = ready_contracts_rx
                .blocking_recv()
                .context("should have gotten all of the compressed")?;
            await_time += started_at.elapsed();

            {
                let DeployedContract { hash, address, .. } =
                    deploy.as_ref().expect("every fetched has a deploy");
                assert_eq!(fetched_address.0, address.0);
                anyhow::ensure!(
                    payload.hash == hash.0,
                    "Contract hash mismatch on address {}: expected {}, actual {}",
                    address.0,
                    hash.0,
                    payload.hash,
                );
            }

            ContractCodeTable::insert_compressed(
                db,
                ContractHash(payload.hash),
                &payload.abi,
                &payload.bytecode,
                &payload.definition,
            )
            .with_context(|| format!("Inserting contract {}", payload.hash))?;

            awaited += 1;
        }

        if let Some(deploy_info) = deploy {
            let state_hash =
                calculate_contract_state_hash(deploy_info.hash, ContractRoot(StarkHash::ZERO));

            global_tree
                .set(address, state_hash)
                .context("Adding deployed contract to global state tree")?;

            // if the deployment block has updates for this contract, we can leave out the insert
            // as one will be provided for it.
            if update.is_none() {
                ContractsStateTable::insert(
                    db,
                    state_hash,
                    deploy_info.hash,
                    ContractRoot(StarkHash::ZERO),
                )
                .context("Insert constract state hash into contracts state table")?;
            }

            ContractsTable::insert(db, address, deploy_info.hash).with_context(|| {
                format!(
                    "Inserting into contracts table for {} => {}",
                    address.0, deploy_info.hash.0
                )
            })?;

            deployed_contract_count += 1;
        }

        if let Some(contract_update) = update {
            total_updates += contract_update.storage_updates.len();

            let contract_state_hash = update_contract_state(&contract_update, &global_tree, db)
                .context("Updating contract state")?;

            global_tree
                .set(address, contract_state_hash)
                .context("Updating global state tree")?;

            updated_contracts += 1;
        }
    }

    assert_eq!(fetch_command_count, awaited);

    // Apply all global tree changes.
    let new_global_root = global_tree
        .apply()
        .context("Applying global state tree updates")?;

    // Validate calculated root against the one received from L1.
    anyhow::ensure!(
        new_global_root == update_log.global_root,
        "New global state root did not match L1."
    );

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
            deployed_contract_count,
            updated_contracts,
            total_updates,
            await_time,
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
    await_time: std::time::Duration,
}

impl std::fmt::Display for BlockInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} deployed contracts, {} contracts updated with total of {} updates, awaited {:?}",
            self.deployed_contract_count,
            self.updated_contracts,
            self.total_updates,
            self.await_time,
        )
    }
}

/// TreeUpdate represents a per contract update to the trees, and is used to order the updates.
#[derive(PartialEq)]
enum TreeUpdate {
    // Option needed to transform this into UpdateDeploy
    Update(Option<ContractUpdate>),
    Deploy(DeployedContract, FetchOrder),
    // TODO: Could inline the CU and DC to avoid duplicating the field
    UpdateDeploy(ContractUpdate, DeployedContract, FetchOrder),
}

impl From<ContractUpdate> for TreeUpdate {
    fn from(u: ContractUpdate) -> Self {
        TreeUpdate::Update(Some(u))
    }
}

impl std::fmt::Debug for TreeUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Update(u) => {
                write!(f, "Update({})", u.as_ref().unwrap().address.0)
            }
            Self::Deploy(d, fo) => {
                write!(f, "Deploy({}, {:?})", d.address.0, fo)
            }
            Self::UpdateDeploy(_, d, fo) => {
                write!(f, "UpdateDeploy({}, {:?}", d.address.0, fo)
            }
        }
    }
}

impl TreeUpdate {
    fn with_deploy(&mut self, d: DeployedContract, fetch_order: FetchOrder) {
        use TreeUpdate::*;
        match self {
            Update(u) => {
                // FIXME: this belongs to a new type combining the two
                assert_eq!(u.as_ref().unwrap().address.0, d.address.0);
                *self = UpdateDeploy(u.take().unwrap(), d, fetch_order)
            }
            _ => unreachable!(),
        }
    }

    fn as_fetch_command(&self) -> Option<FetchExtractContract> {
        use FetchOrder::FetchedNth;
        use TreeUpdate::*;
        match self {
            Deploy(d, FetchedNth(_)) | UpdateDeploy(_, d, FetchedNth(_)) => {
                Some(FetchExtractContract(d.address))
            }
            _ => None,
        }
    }
}

/// Records the needs of a [`TreeUpdate`] in relation to contract definition fetching in an update
/// batch.
#[derive(PartialEq, Eq, Debug)]
enum FetchOrder {
    /// This represents a contract which should be fetched in this order
    FetchedNth(usize),
    /// This represents a contract which uses previously fetched
    UsingNthFetched(usize),
    /// This represents a contract which we already have
    ExistsAlready,
}

impl std::cmp::PartialOrd for FetchOrder {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for FetchOrder {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::*;
        use FetchOrder::*;

        match (self, other) {
            // we should always handle these first
            (ExistsAlready, ExistsAlready) => Equal,
            (ExistsAlready, _) => Less,
            (_, ExistsAlready) => Greater,

            (FetchedNth(x), FetchedNth(y)) | (UsingNthFetched(x), UsingNthFetched(y)) => x.cmp(y),

            (FetchedNth(x), UsingNthFetched(y)) => x.cmp(y).then(Less),
            (UsingNthFetched(x), FetchedNth(y)) => x.cmp(y).then(Greater),
        }
    }
}

impl FetchOrder {
    /// Returns true if this fetch order implies that a network request should be done
    fn implies_fetch(&self) -> bool {
        match self {
            FetchOrder::FetchedNth(_) => true,
            _ => false,
        }
    }
}

fn combine_to_tree_updates(
    db: &rusqlite::Transaction,
    deployed: Vec<DeployedContract>,
    updated: Vec<ContractUpdate>,
) -> Result<Vec<TreeUpdate>, rusqlite::Error> {
    let mut tree_updates = HashMap::with_capacity(deployed.len() + updated.len());

    tree_updates.extend(
        updated
            .into_iter()
            .map(|u| (u.address, TreeUpdate::from(u))),
    );

    // mapping from already known contract hashes to an option of in which order we will be
    // fetching this contract, or none, meaning for it already existing in our database
    //
    // using the default hashmap here is fine, since we are bound to get deterministic order from
    // the deployed being a vec, which sets the order for the FetchOrder and so the order for the
    // fetched contracts on the final sort.
    let mut already_fetching: HashMap<StarkHash, Option<usize>> =
        HashMap::with_capacity(deployed.len());

    let mut fetches = 0;

    let mut stmt = db
        .prepare("select 1 from contract_code where hash = ?")
        .unwrap();

    for x in deployed {
        use std::collections::hash_map::Entry::*;

        let fetch_order = match already_fetching.entry(x.hash.0) {
            Occupied(oe) => match oe.get() {
                Some(order) => FetchOrder::UsingNthFetched(*order),
                None => FetchOrder::ExistsAlready,
            },
            Vacant(ve) => {
                let known = stmt.exists(&[&x.hash.0.to_be_bytes()[..]])?;

                if !known {
                    let order = fetches;
                    fetches += 1;
                    ve.insert(Some(order));
                    FetchOrder::FetchedNth(order)
                } else {
                    // we have it our database
                    ve.insert(None);
                    FetchOrder::ExistsAlready
                }
            }
        };

        match tree_updates.entry(x.address) {
            Occupied(mut oe) => {
                let val = oe.get_mut();
                val.with_deploy(x, fetch_order);
            }
            Vacant(ve) => {
                ve.insert(TreeUpdate::Deploy(x, fetch_order));
            }
        }
    }

    let mut tree_updates = tree_updates
        .into_iter()
        .map(|(_k, v)| v)
        .collect::<Vec<_>>();

    // we don't really care about the sort between individual contracts. for testing this might be
    // good to set to the stable sort, but we don't need it in reality.
    //
    // NOTE: this sort function should not be set as the PartialOrd or Ord because it doesn't sort
    // by every field in the graph, just does a quick and easy "sort by type".
    tree_updates.sort_unstable_by(|l, r| {
        use std::cmp::Ordering::*;
        use TreeUpdate::*;

        // for the ordering of TreeUpdates, we want the first be updates of existing contracts then
        // the deploys and/or updates in the order of their fetches to maximize the work done
        // before each fetch.
        match (l, r) {
            (Update(_), Update(_)) => Equal,
            (Update(_), _) => Less,
            (_, Update(_)) => Greater,
            (UpdateDeploy(_, _, l_fo), UpdateDeploy(_, _, r_fo))
            | (Deploy(_, l_fo), Deploy(_, r_fo))
            | (UpdateDeploy(_, _, l_fo), Deploy(_, r_fo))
            | (Deploy(_, l_fo), UpdateDeploy(_, _, r_fo)) => l_fo.cmp(r_fo),
        }
    });

    Ok(tree_updates)
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

    #[test]
    fn update_requests_fetching_unique_new_contracts() {
        use super::{combine_to_tree_updates, FetchExtractContract, FetchOrder::*, TreeUpdate};
        use crate::core::{ContractAddress, StorageAddress, StorageValue};
        use crate::ethereum::state_update::{
            ContractUpdate, DeployedContract, StateUpdate, StorageUpdate,
        };
        let s = crate::storage::Storage::in_memory().unwrap();
        let mut conn = s.connection().unwrap();
        let db = conn.transaction().unwrap();

        let shared_hash =
            ContractHash(StarkHash::from_be_slice(&b"this is shared by multiple"[..]).unwrap());
        let unique_hash =
            ContractHash(StarkHash::from_be_slice(&b"this is unique contract"[..]).unwrap());
        let existing_hash =
            ContractHash(StarkHash::from_be_slice(&b"used to test contract exists"[..]).unwrap());

        let one = ContractAddress(StarkHash::from_hex_str("1").unwrap());
        let two = ContractAddress(StarkHash::from_hex_str("2").unwrap());
        let three = ContractAddress(StarkHash::from_hex_str("3").unwrap());
        let already_deployed = ContractAddress(StarkHash::from_hex_str("4").unwrap());
        let already_existing = ContractAddress(StarkHash::from_hex_str("5").unwrap());

        db.execute(
            "insert into contract_code (hash, abi, bytecode, definition) values (?1, ?2, ?3, ?4)",
            [
                &existing_hash.0.to_be_bytes()[..],
                &[][..],
                &[][..],
                &[][..],
            ],
        )
        .unwrap();

        let one_deploy = DeployedContract {
            address: one,
            hash: shared_hash,
            call_data: vec![],
        };

        let two_deploy = DeployedContract {
            address: two,
            hash: shared_hash,
            call_data: vec![],
        };

        let three_deploy = DeployedContract {
            address: three,
            hash: unique_hash,
            call_data: vec![],
        };

        let fifth_deploy = DeployedContract {
            address: already_existing,
            hash: existing_hash,
            call_data: vec![],
        };

        let one_update = ContractUpdate {
            address: one,
            storage_updates: vec![StorageUpdate {
                address: StorageAddress(StarkHash::from_hex_str("1").unwrap()),
                value: StorageValue(StarkHash::from_hex_str("dead").unwrap()),
            }],
        };

        let already_deployed_update = ContractUpdate {
            address: already_deployed,
            storage_updates: vec![StorageUpdate {
                address: StorageAddress(StarkHash::from_hex_str("cafe").unwrap()),
                value: StorageValue(StarkHash::from_hex_str("babe").unwrap()),
            }],
        };

        // neither of these deployed contracts are in database, which is empty
        let state_update = StateUpdate {
            deployed_contracts: vec![
                one_deploy.clone(),
                two_deploy.clone(),
                three_deploy.clone(),
                fifth_deploy.clone(),
            ],
            contract_updates: vec![one_update.clone(), already_deployed_update.clone()],
        };

        let tree_updates = combine_to_tree_updates(
            &db,
            state_update.deployed_contracts,
            state_update.contract_updates,
        )
        .unwrap();

        assert_eq!(
            tree_updates,
            vec![
                TreeUpdate::Update(Some(already_deployed_update)),
                TreeUpdate::Deploy(fifth_deploy.clone(), ExistsAlready),
                TreeUpdate::UpdateDeploy(one_update, one_deploy.clone(), FetchedNth(0)),
                TreeUpdate::Deploy(two_deploy, UsingNthFetched(0)),
                TreeUpdate::Deploy(three_deploy.clone(), FetchedNth(1)),
            ]
        );

        assert_eq!(
            tree_updates
                .iter()
                .filter_map(TreeUpdate::as_fetch_command)
                .collect::<Vec<_>>(),
            vec![FetchExtractContract(one), FetchExtractContract(three)]
        );
    }

    #[test]
    fn fetch_order_orderings() {
        use super::FetchOrder::*;

        assert!(ExistsAlready < FetchedNth(0));
        assert!(FetchedNth(0) < UsingNthFetched(0));
        assert!(UsingNthFetched(0) < FetchedNth(1));
        assert!(FetchedNth(1) > UsingNthFetched(0));
    }

    #[tokio::test]
    #[ignore = "Sequencer currently gives 502/503"]
    async fn genesis() {
        use crate::core::{
            EthereumBlockHash, EthereumBlockNumber, EthereumLogIndex, EthereumTransactionHash,
            EthereumTransactionIndex, GlobalRoot, StarknetBlockHash, StarknetBlockNumber,
        };
        use crate::ethereum::{
            log::StateUpdateLog, test::create_test_transport, BlockOrigin, EthOrigin,
            TransactionOrigin,
        };
        use std::str::FromStr;
        use web3::types::H256;
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

        let _sequencer = crate::sequencer::Client::goerli().unwrap();

        let storage = crate::storage::Storage::in_memory().unwrap();
        let mut conn = storage.connection().unwrap();
        let transaction = conn.transaction().unwrap();

        let _transport = create_test_transport(crate::ethereum::Chain::Goerli);

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

        // TODO: "is this test supposed to be sync for one block?

        // Read the new latest state from database.
        let state = crate::storage::GlobalStateTable::get_latest_state(&transaction)
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
    }

    #[tokio::test]
    #[ignore] // this is manual testing only, but we should really use the binary for this
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
