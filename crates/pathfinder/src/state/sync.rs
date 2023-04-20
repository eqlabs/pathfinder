pub mod l2;
mod pending;

use anyhow::Context;
use pathfinder_common::{
    Chain, ClassCommitment, ClassHash, ContractNonce, ContractRoot, EventCommitment, GasPrice,
    SequencerAddress, StarknetBlockHash, StarknetBlockNumber, StateCommitment, StorageCommitment,
    TransactionCommitment,
};
use pathfinder_ethereum::{bsearch_starknet_matching_block, StarknetEthereumClient};
use pathfinder_merkle_tree::{
    contract_state::{calculate_contract_state_hash, update_contract_state},
    ClassCommitmentTree, StorageCommitmentTree,
};
use pathfinder_rpc::{
    v02::types::syncing::{self, NumberedBlock, Syncing},
    SyncState,
};
use pathfinder_storage::{
    types::{CompressedCasmClass, CompressedContract},
    CasmClassTable, ClassCommitmentLeavesTable, ContractCodeTable, ContractsStateTable, RefsTable,
    StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable, StarknetStateUpdatesTable,
    StarknetTransactionsTable, Storage,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use stark_hash::Felt;
use starknet_gateway_client::ClientApi;
use starknet_gateway_types::{
    pending::PendingData,
    reply::{
        state_update::DeployedContract, Block, MaybePendingBlock, PendingStateUpdate, StateUpdate,
    },
};
use std::sync::Arc;
use std::{collections::HashMap, future::Future};
use tokio::sync::mpsc;

async fn find_matching_ethereum_block(
    client: &StarknetEthereumClient,
    block: &Block,
    current_head: u64,
) -> anyhow::Result<u64> {
    let eth_block_num =
        bsearch_starknet_matching_block(client, block.block_number.0, current_head).await?;
    let eth_block_hash = client.eth.get_block_hash(eth_block_num).await?;
    let expected_state_root = client.get_starknet_state_root(&eth_block_hash).await?;
    let expected_state_root = expected_state_root.as_bytes();
    let received_state_root = block.state_commitment.0.as_ref();

    if received_state_root == expected_state_root {
        Ok(eth_block_num.as_u64())
    } else {
        Err(anyhow::anyhow!(
            "Block state root mismatch: block={} expected={:?} received={:?}",
            block.block_number,
            expected_state_root,
            received_state_root
        ))
    }
}

/// Implements the main sync loop, where L1 and L2 sync results are combined.
#[allow(clippy::too_many_arguments)]
pub async fn sync<SequencerClient, F, L2Sync>(
    storage: Storage,
    ethereum_client: StarknetEthereumClient,
    chain: Chain,
    sequencer: SequencerClient,
    state: Arc<SyncState>,
    l2_sync: L2Sync,
    pending_data: PendingData,
    pending_poll_interval: Option<std::time::Duration>,
    block_validation_mode: l2::BlockValidationMode,
) -> anyhow::Result<()>
where
    SequencerClient: ClientApi + Clone + Send + Sync + 'static,
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
    L2Sync: FnOnce(
            mpsc::Sender<l2::Event>,
            SequencerClient,
            Option<(StarknetBlockNumber, StarknetBlockHash, StateCommitment)>,
            Chain,
            Option<std::time::Duration>,
            std::time::Duration,
            l2::BlockValidationMode,
        ) -> F
        + Copy,
{
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (tx_l2, mut rx_l2) = mpsc::channel(1);

    let l2_head = tokio::task::block_in_place(|| -> anyhow::Result<_> {
        let tx = db_conn.transaction()?;
        let l2_head = StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
            .context("Query L2 head from database")?
            .map(|block| (block.number, block.hash, block.root));
        Ok(l2_head)
    })?;

    // Start update sync-status process.
    let (starting_block_num, starting_block_hash, _) = l2_head.unwrap_or((
        // Seems a better choice for an invalid block number than 0
        StarknetBlockNumber::MAX,
        StarknetBlockHash(Felt::ZERO),
        StateCommitment(Felt::ZERO),
    ));
    let _status_sync = tokio::spawn(update_sync_status_latest(
        Arc::clone(&state),
        sequencer.clone(),
        starting_block_hash,
        starting_block_num,
        chain,
    ));

    // Start L1 and L2 sync processes.
    let no_delay = std::time::Duration::ZERO;
    let mut l2_handle = tokio::spawn(l2_sync(
        tx_l2,
        sequencer.clone(),
        l2_head,
        chain,
        pending_poll_interval,
        no_delay,
        block_validation_mode,
    ));

    let mut existed = (0, 0);

    let mut last_block_start = std::time::Instant::now();
    let mut block_time_avg = std::time::Duration::ZERO;
    const BLOCK_TIME_WEIGHT: f32 = 0.05;

    // Delay before restarting L1 or L2 tasks if they fail.
    const RESTART_DELAY: std::time::Duration = std::time::Duration::from_secs(60);

    loop {
        tokio::select! {
            l2_event = rx_l2.recv() => match l2_event {
                Some(l2::Event::Update((block, (tx_comm, ev_comm)), state_update, timings)) => {
                    pending_data.clear().await;

                    let current_head = {
                        let tx = db_conn.transaction().context("db tx")?;
                        RefsTable::get_l1_l2_head(&tx).unwrap_or_default().map(|x| x.0).unwrap_or_default()
                    };
                    match find_matching_ethereum_block(&ethereum_client, &block, current_head).await {
                        Ok(ethereum_block_number) => {
                            let tx = db_conn.transaction().context("db tx")?;
                            RefsTable::set_l1_l2_head(&tx, Some(StarknetBlockNumber(ethereum_block_number)))?;
                            tx.commit().context("db tx commit")?;
                            tracing::info!(block=ethereum_block_number, "L1 head update");
                        },
                        Err(e) => tracing::error!("{e}"),
                    }

                    let block_number = block.block_number;
                    let block_hash = block.block_hash;
                    let storage_updates: usize = state_update.state_diff.storage_diffs.values().map(|storage_diffs| storage_diffs.len()).sum();
                    let update_t = std::time::Instant::now();
                    l2_update(&mut db_conn, *block, tx_comm, ev_comm, *state_update)
                        .await
                        .with_context(|| format!("Update L2 state to {block_number}"))?;
                    let block_time = last_block_start.elapsed();
                    let update_t = update_t.elapsed();
                    last_block_start = std::time::Instant::now();

                    block_time_avg = block_time_avg.mul_f32(1.0 - BLOCK_TIME_WEIGHT)
                        + block_time.mul_f32(BLOCK_TIME_WEIGHT);

                    // Update sync status
                    match &mut *state.status.write().await {
                        Syncing::False(_) => {}
                        Syncing::Status(status) => {
                            status.current = NumberedBlock::from((block_hash, block_number));

                            if status.highest.number <= block_number {
                                status.highest = status.current;
                            }
                        }
                    }

                    tracing::info!(block=block_number.0, "StarkNet state update");
                    let is_debug = tracing::level_filters::LevelFilter::current().into_level()
                        .map(|level| level <= tracing::Level::DEBUG)
                        .unwrap_or_default();
                    if is_debug  {
                        tracing::debug!("Updated StarkNet state with block {} after {:2}s ({:2}s avg). {} ({} new) contracts ({:2}s), {} storage updates ({:2}s). Block downloaded in {:2}s, state diff in {:2}s",
                            block_number,
                            block_time.as_secs_f32(),
                            block_time_avg.as_secs_f32(),
                            existed.0,
                            existed.0 - existed.1,
                            timings.class_declaration.as_secs_f32(),
                            storage_updates,
                            update_t.as_secs_f32(),
                            timings.block_download.as_secs_f32(),
                            timings.state_diff_download.as_secs_f32(),
                        );
                    }
                }
                Some(l2::Event::Reorg(reorg_tail)) => {
                    pending_data.clear().await;

                    l2_reorg(&mut db_conn, reorg_tail)
                        .await
                        .with_context(|| format!("Reorg L2 state to {reorg_tail:?}"))?;

                    let new_head = match reorg_tail {
                        StarknetBlockNumber::GENESIS => None,
                        other => Some(other - 1),
                    };
                    match new_head {
                        Some(head) => {
                            tracing::info!("L2 reorg occurred, new L2 head is block {}", head)
                        }
                        None => tracing::info!("L2 reorg occurred, new L2 head is genesis"),
                    }
                }
                Some(l2::Event::NewCairoContract(contract)) => {
                    tokio::task::block_in_place(|| {
                        ContractCodeTable::insert_compressed(&db_conn, &contract)
                    })
                    .with_context(|| {
                        format!("Insert Cairo contract definition with hash: {:?}", contract.hash)
                    })?;

                    tracing::trace!("Inserted new Cairo contract {}", contract.hash.0.to_hex_str());
                }
                Some(l2::Event::NewSierraContract(sierra_class, casm_class, compiled_class_hash)) => {
                    tokio::task::block_in_place(|| {
                        ContractCodeTable::insert_compressed(&db_conn, &sierra_class)?;
                        CasmClassTable::upsert_compressed(&db_conn, &casm_class, &compiled_class_hash, crate::sierra::COMPILER_VERSION)
                    })
                    .with_context(|| {
                        format!("Insert Sierra contract definition with hash: {:?}", sierra_class.hash)
                    })?;

                    tracing::trace!("Inserted new Sierra contract {}", sierra_class.hash.0.to_hex_str());
                }
                Some(l2::Event::QueryBlock(number, tx)) => {
                    let block = tokio::task::block_in_place(|| {
                        let tx = db_conn.transaction()?;
                        StarknetBlocksTable::get(&tx, number.into())
                    })
                    .with_context(|| format!("Query L2 block hash for block {number}"))?
                    .map(|block| (block.hash, block.root));
                    let _ = tx.send(block);

                    tracing::trace!(%number, "Query hash for L2 block");
                }
                Some(l2::Event::QueryContractExistance(contracts, tx)) => {
                    let exists =
                        tokio::task::block_in_place(|| {
                            let tx = db_conn.transaction()?;
                            ContractCodeTable::exists(&tx, &contracts)
                        })
                        .with_context(|| {
                            format!("Query storage for existance of contracts {contracts:?}")
                        })?;
                    let count = exists.iter().filter(|b| **b).count();

                    // Fixme: This stat tracking is now incorrect, as these are shared by deploy and declare.
                    //        Overall, quite nasty as is, so should get a proper refactor instead.
                    existed = (contracts.len(), count);

                    let _ = tx.send(exists);

                    tracing::trace!("Query for existence of contracts: {:?}", contracts);
                }
                Some(l2::Event::Pending(block, state_update)) => {
                    download_verify_and_insert_missing_classes(sequencer.clone(), &mut db_conn, &state_update, chain)
                        .await
                        .context("Downloading missing classes for pending block")?;

                    pending_data.set(block, state_update).await;
                    tracing::debug!("Updated pending data");
                }
                None => {
                    pending_data.clear().await;
                    // L2 sync process failed; restart it.
                    match l2_handle.await.context("Join L2 sync process handle")? {
                        Ok(()) => {
                            tracing::error!("L2 sync process terminated without an error.");
                        }
                        Err(e) => {
                            tracing::warn!("L2 sync process terminated with: {:?}", e);
                        }
                    }

                    let l2_head = tokio::task::block_in_place(|| {
                        let tx = db_conn.transaction()?;
                        StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
                    })
                    .context("Query L2 head from database")?
                    .map(|block| (block.number, block.hash, block.root));

                    let (new_tx, new_rx) = mpsc::channel(1);
                    rx_l2 = new_rx;

                    let fut = l2_sync(new_tx, sequencer.clone(), l2_head, chain, pending_poll_interval, RESTART_DELAY, block_validation_mode);

                    l2_handle = tokio::spawn(async move { fut.await });
                    tracing::info!("L2 sync process restarted.");
                }
            }
        }
    }
}

/// Periodically updates sync state with the latest block height.
async fn update_sync_status_latest(
    state: Arc<SyncState>,
    sequencer: impl ClientApi,
    starting_block_hash: StarknetBlockHash,
    starting_block_num: StarknetBlockNumber,
    chain: Chain,
) -> anyhow::Result<()> {
    use pathfinder_common::BlockId;

    let poll_interval = head_poll_interval(chain);

    let starting = NumberedBlock::from((starting_block_hash, starting_block_num));

    loop {
        match sequencer.block(BlockId::Latest).await {
            Ok(MaybePendingBlock::Block(block)) => {
                let latest = {
                    let latest_hash = block.block_hash;
                    let latest_num = block.block_number;
                    NumberedBlock::from((latest_hash, latest_num))
                };
                // Update the sync status.
                match &mut *state.status.write().await {
                    sync_status @ Syncing::False(_) => {
                        *sync_status = Syncing::Status(syncing::Status {
                            starting,
                            current: starting,
                            highest: latest,
                        });

                        tracing::debug!(
                            status=%sync_status,
                            "Updated sync status",
                        );
                    }
                    Syncing::Status(status) => {
                        if status.highest.hash != latest.hash {
                            status.highest = latest;

                            tracing::debug!(
                                %status,
                                "Updated sync status",
                            );
                        }
                    }
                }
            }
            Ok(MaybePendingBlock::Pending(_)) => {
                tracing::error!("Latest block returned 'pending'");
            }
            Err(e) => {
                tracing::error!(error=%e, "Failed to fetch latest block");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Returns the new [StateCommitment] after the update.
async fn l2_update(
    connection: &mut Connection,
    block: Block,
    tx_commitment: TransactionCommitment,
    ev_commitment: EventCommitment,
    state_update: StateUpdate,
) -> anyhow::Result<()> {
    use pathfinder_storage::CanonicalBlocksTable;

    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        let (new_storage_commitment, new_class_commitment) =
            update_starknet_state(&transaction, &state_update)
                .context("Updating Starknet state")?;
        let new_root = StateCommitment::calculate(new_storage_commitment, new_class_commitment);

        // Ensure that roots match.. what should we do if it doesn't? For now the whole sync process ends..
        anyhow::ensure!(new_root == block.state_commitment, "State root mismatch");

        // Update L2 database. These types shouldn't be options at this level,
        // but for now the unwraps are "safe" in that these should only ever be
        // None for pending queries to the sequencer, but we aren't using those here.
        let starknet_block = StarknetBlock {
            number: block.block_number,
            hash: block.block_hash,
            root: block.state_commitment,
            timestamp: block.timestamp,
            // Default value for cairo <0.8.2 is 0
            gas_price: block.gas_price.unwrap_or(GasPrice::ZERO),
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(Felt::ZERO)),
            transaction_commitment: Some(tx_commitment),
            event_commitment: Some(ev_commitment),
        };
        StarknetBlocksTable::insert(
            &transaction,
            &starknet_block,
            block.starknet_version.as_deref(),
            new_storage_commitment,
            new_class_commitment,
        )
        .context("Insert block into database")?;

        let rpc_state_update = state_update.into();
        StarknetStateUpdatesTable::insert(&transaction, block.block_hash, &rpc_state_update)
            .context("Insert state update into database")?;

        CanonicalBlocksTable::insert(&transaction, block.block_number, block.block_hash)
            .context("Inserting canonical block into database")?;

        let declared_sierra_class_hashes = rpc_state_update
            .state_diff
            .declared_sierra_classes
            .iter()
            .map(|c| ClassHash(c.class_hash.0));
        let declared_cairo_class_hashes = rpc_state_update
            .state_diff
            .declared_contracts
            .iter()
            .map(|c| c.class_hash);
        let deployed_class_hashes = rpc_state_update
            .state_diff
            .deployed_contracts
            .iter()
            .map(|d| d.class_hash);
        let declared_class_hashes = declared_sierra_class_hashes
            .chain(declared_cairo_class_hashes)
            .chain(deployed_class_hashes);
        for class_hash in declared_class_hashes {
            ContractCodeTable::update_declared_on_if_null(
                &transaction,
                class_hash,
                block.block_hash,
            )
            .with_context(|| format!("Setting declared_on for class={:?}", class_hash))?;
        }

        // Insert the transactions.
        anyhow::ensure!(
            block.transactions.len() == block.transaction_receipts.len(),
            "Transactions and receipts mismatch. There were {} transactions and {} receipts.",
            block.transactions.len(),
            block.transaction_receipts.len()
        );
        let transaction_data = block
            .transactions
            .into_iter()
            .zip(block.transaction_receipts.into_iter())
            .collect::<Vec<_>>();
        StarknetTransactionsTable::upsert(
            &transaction,
            starknet_block.hash,
            starknet_block.number,
            &transaction_data,
        )
        .context("Insert transaction data into database")?;

        RefsTable::set_l1_l2_head(&transaction, Some(starknet_block.number))
            .context("Update L1-L2 head")?;

        transaction.commit().context("Commit database transaction")
    })
}

async fn l2_reorg(
    connection: &mut Connection,
    reorg_tail: StarknetBlockNumber,
) -> anyhow::Result<()> {
    use pathfinder_storage::CanonicalBlocksTable;

    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        CanonicalBlocksTable::reorg(&transaction, reorg_tail)
            .context("Delete canonical blocks from database")?;

        StarknetBlocksTable::reorg(&transaction, reorg_tail)
            .context("Delete L2 blocks from database")?;

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        match l1_l2_head {
            Some(head) if head >= reorg_tail => {
                let new_head = match reorg_tail {
                    StarknetBlockNumber::GENESIS => None,
                    other => Some(other - 1),
                };
                RefsTable::set_l1_l2_head(&transaction, new_head).context("Update L1-L2 head")?;
            }
            _ => {}
        }

        transaction.commit().context("Commit database transaction")
    })
}

fn update_starknet_state(
    transaction: &Transaction<'_>,
    state_update: &StateUpdate,
) -> anyhow::Result<(StorageCommitment, ClassCommitment)> {
    let (storage_commitment, class_commitment) =
        StarknetBlocksTable::get_state_commitment(transaction, StarknetBlocksBlockId::Latest)
            .context("Query latest state commitment")?
            .unwrap_or((StorageCommitment::ZERO, ClassCommitment::ZERO));

    let mut storage_commitment_tree = StorageCommitmentTree::load(transaction, storage_commitment);

    for contract in &state_update.state_diff.deployed_contracts {
        deploy_contract(transaction, &mut storage_commitment_tree, contract)
            .context("Deploying contract")?;
    }

    // Copied so we can mutate the map. This lets us remove used nonces from the list.
    let mut nonces = state_update.state_diff.nonces.clone();

    let mut replaced_classes = state_update
        .state_diff
        .replaced_classes
        .iter()
        .map(|r| (r.address, r.class_hash))
        .collect::<HashMap<_, _>>();

    // Apply contract storage updates.
    for (contract_address, updates) in &state_update.state_diff.storage_diffs {
        // Remove the nonce so we don't update it again in the next stage.
        let nonce = nonces.remove(contract_address);
        // Remove from replaced classes so we don't update it again in the next stage.
        let replaced_class_hash = replaced_classes.remove(contract_address);

        let contract_state_hash = update_contract_state(
            *contract_address,
            updates,
            nonce,
            replaced_class_hash,
            &storage_commitment_tree,
            transaction,
        )
        .context("Update contract state")?;

        // Update the global state tree.
        storage_commitment_tree
            .set(*contract_address, contract_state_hash)
            .context("Updating storage commitment tree")?;
    }

    // Apply all remaining nonces (without storage updates).
    for (contract_address, nonce) in nonces {
        // Remove from replaced classes so we don't update it again in the next stage.
        let replaced_class_hash = replaced_classes.remove(&contract_address);

        let contract_state_hash = update_contract_state(
            contract_address,
            &[],
            Some(nonce),
            replaced_class_hash,
            &storage_commitment_tree,
            transaction,
        )
        .context("Update contract nonce")?;

        // Update the global state tree.
        storage_commitment_tree
            .set(contract_address, contract_state_hash)
            .context("Updating storage commitment tree")?;
    }

    // Apply all remaining replaced classes.
    for (contract_address, new_class_hash) in replaced_classes {
        let contract_state_hash = update_contract_state(
            contract_address,
            &[],
            None,
            Some(new_class_hash),
            &storage_commitment_tree,
            transaction,
        )
        .context("Update contract nonce")?;

        // Update the global state tree.
        storage_commitment_tree
            .set(contract_address, contract_state_hash)
            .context("Updating storage commitment tree")?;
    }

    // Apply storage commitment tree changes.
    let new_storage_commitment = storage_commitment_tree
        .commit_and_persist_changes()
        .context("Apply storage commitment tree updates")?;

    // Add new Sierra classes to class commitment tree.
    let mut class_commitment_tree = ClassCommitmentTree::load(transaction, class_commitment);

    for sierra_class in &state_update.state_diff.declared_classes {
        let leaf_hash = pathfinder_common::calculate_class_commitment_leaf_hash(
            sierra_class.compiled_class_hash,
        );

        ClassCommitmentLeavesTable::upsert(
            transaction,
            &leaf_hash,
            &sierra_class.compiled_class_hash,
        )
        .context("Adding class commitment leaf")?;

        class_commitment_tree
            .set(sierra_class.class_hash, leaf_hash)
            .context("Update class commitment tree")?;
    }

    // Apply all class commitment tree changes.
    let new_class_commitment = class_commitment_tree
        .commit_and_persist_changes()
        .context("Apply class commitment tree updates")?;

    Ok((new_storage_commitment, new_class_commitment))
}

fn deploy_contract(
    transaction: &Transaction<'_>,
    storage_commitment_tree: &mut StorageCommitmentTree<'_>,
    contract: &DeployedContract,
) -> anyhow::Result<()> {
    // Add a new contract to global tree, the contract root is initialized to ZERO.
    let contract_root = ContractRoot::ZERO;
    // The initial value of a contract nonce is ZERO.
    let contract_nonce = ContractNonce::ZERO;
    // sequencer::reply::state_update::Contract::contract_hash is the old (pre cairo 0.9.0)
    // name for `class_hash`.
    let class_hash = contract.class_hash;
    let state_hash = calculate_contract_state_hash(class_hash, contract_root, contract_nonce);
    storage_commitment_tree
        .set(contract.address, state_hash)
        .context("Adding deployed contract to global state tree")?;
    ContractsStateTable::upsert(
        transaction,
        state_hash,
        class_hash,
        contract_root,
        contract_nonce,
    )
    .context("Insert constract state hash into contracts state table")
}

/// Downloads and inserts class definitions for any classes in the
/// list which are not already present in the database.
async fn download_verify_and_insert_missing_classes<SequencerClient: ClientApi>(
    sequencer: SequencerClient,
    connection: &mut Connection,
    state_update: &PendingStateUpdate,
    chain: Chain,
) -> anyhow::Result<()> {
    let deployed_classes = state_update
        .state_diff
        .deployed_contracts
        .iter()
        .map(|x| x.class_hash);
    let declared_cairo_classes = state_update
        .state_diff
        .old_declared_contracts
        .iter()
        .cloned();
    let declared_sierra_classes = state_update
        .state_diff
        .declared_classes
        .iter()
        .map(|x| ClassHash(x.class_hash.0));
    let replaced_classes = state_update
        .state_diff
        .replaced_classes
        .iter()
        .map(|x| x.class_hash);

    let classes = deployed_classes
        .chain(declared_cairo_classes)
        .chain(declared_sierra_classes)
        .chain(replaced_classes);

    // Make list unique.
    let classes = classes
        .collect::<std::collections::HashSet<_>>()
        .into_iter() // TODO: remove this allocation by using Iter in exists.
        .collect::<Vec<_>>();

    // Check database to see which are missing.
    let exists = tokio::task::block_in_place(|| {
        let transaction = connection.transaction()?;
        ContractCodeTable::exists(&transaction, &classes)
    })
    .with_context(|| format!("Query storage for existance of classes {classes:?}"))?;
    anyhow::ensure!(
        exists.len() == classes.len(),
        "Length mismatch when querying for class existance. Expected {} but got {}.",
        classes.len(),
        exists.len()
    );
    let missing = classes
        .into_iter()
        .zip(exists.into_iter())
        .filter_map(|(class, exist)| (!exist).then_some(class));

    // For each missing, download, verify and insert definition.
    for class_hash in missing {
        let class = download_class(&sequencer, class_hash, chain).await?;

        match class {
            DownloadedClass::Cairo(class) => {
                tokio::task::block_in_place(|| {
                    let transaction =
                        connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    ContractCodeTable::insert_compressed(&transaction, &class)?;
                    transaction.commit()?;
                    anyhow::Result::<()>::Ok(())
                })
                .with_context(|| format!("Insert class definition with hash: {:?}", class.hash))?;
            }
            DownloadedClass::Sierra(sierra, casm) => {
                // NOTE: we _have_ to use the same compiled_class_class hash as returned by the feeder gateway,
                // since that's what has been added to the class commitment tree.
                let compiled_class_hash = state_update
                    .state_diff
                    .declared_classes
                    .iter()
                    .find_map(|declared_class| {
                        if declared_class.class_hash.0 == class_hash.0 {
                            Some(declared_class.compiled_class_hash)
                        } else {
                            None
                        }
                    })
                    .context("Sierra class hash not in declared classes")?;
                tokio::task::block_in_place(|| {
                    let transaction =
                        connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    ContractCodeTable::insert_compressed(&transaction, &sierra)?;
                    CasmClassTable::upsert_compressed(
                        &transaction,
                        &casm,
                        &compiled_class_hash,
                        crate::sierra::COMPILER_VERSION,
                    )?;
                    transaction.commit()?;
                    anyhow::Result::<()>::Ok(())
                })
                .with_context(|| format!("Insert class definition with hash: {:?}", sierra.hash))?;
            }
        }

        tracing::trace!("Inserted new class {}", class_hash.0.to_hex_str());
    }

    Ok(())
}

enum DownloadedClass {
    Cairo(CompressedContract),
    Sierra(CompressedContract, CompressedCasmClass),
}

async fn download_class<SequencerClient: ClientApi>(
    sequencer: &SequencerClient,
    class_hash: ClassHash,
    chain: Chain,
) -> Result<DownloadedClass, anyhow::Error> {
    use starknet_gateway_types::class_hash::compute_class_hash;

    let definition = sequencer
        .pending_class_by_hash(class_hash)
        .await
        .with_context(|| format!("Downloading class {}", class_hash.0))?;

    let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let hash = compute_class_hash(&definition)?;
        Ok((definition, hash))
    });
    let (definition, hash) = extract
        .await
        .context("Parse class definition and compute hash")??;

    anyhow::ensure!(
        class_hash == hash.hash(),
        "Class hash mismatch, {} instead of {}",
        hash.hash(),
        class_hash.0
    );

    match hash {
        starknet_gateway_types::class_hash::ComputedClassHash::Cairo(hash) => {
            let compress = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let mut compressor =
                    zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

                let definition = compressor
                    .compress(&definition)
                    .context("Compress definition")?;

                Ok(definition)
            });
            let compressed_definition = compress.await.context("Compress class")??;

            Ok(DownloadedClass::Cairo(
                pathfinder_storage::types::CompressedContract {
                    definition: compressed_definition,
                    hash,
                },
            ))
        }
        starknet_gateway_types::class_hash::ComputedClassHash::Sierra(hash) => {
            // FIXME(integration reset): work-around for integration containing Sierra classes
            // that are incompatible with production compiler. This will get "fixed" in the future
            // by resetting integration to remove these classes at which point we can revert this.
            //
            // The work-around ignores compilation errors on integration, and instead replaces the
            // casm definition with empty bytes.
            let casm_definition =
                crate::sierra::compile_to_casm(&definition).context("Compiling Sierra class");
            let casm_definition = match (casm_definition, chain) {
                (Ok(casm_definition), _) => casm_definition,
                (Err(_), Chain::Integration) => {
                    tracing::info!(class_hash=%hash, "Ignored CASM compilation failure integration network");
                    Vec::new()
                }
                (Err(e), _) => return Err(e),
            };

            let compress = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let mut compressor =
                    zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

                let definition = compressor
                    .compress(&definition)
                    .context("Compress definition")?;

                let casm_definition = compressor
                    .compress(&casm_definition)
                    .context("Compress CASM definition")?;

                Ok((definition, casm_definition))
            });
            let (compressed_definition, compressed_casm_definition) =
                compress.await.context("Compress class")??;

            Ok(DownloadedClass::Sierra(
                pathfinder_storage::types::CompressedContract {
                    definition: compressed_definition,
                    hash,
                },
                pathfinder_storage::types::CompressedCasmClass {
                    definition: compressed_casm_definition,
                    hash,
                },
            ))
        }
    }
}

/// Interval at which poll for new data when at the head of chain.
///
/// Returns the interval to be used when polling while at the head of the chain. The
/// interval is chosen to provide a good balance between spamming and getting new
/// block information as it is available. The interval is based on the block creation
/// time, which is 2 minutes for Goerlie and 2 hours for Mainnet.
pub fn head_poll_interval(chain: Chain) -> std::time::Duration {
    use pathfinder_common::Chain::*;
    use std::time::Duration;

    match chain {
        // 5 minute interval for a 30 minute block time.
        Mainnet => Duration::from_secs(60 * 5),
        // 30 second interval for a 2 minute block time.
        Testnet | Testnet2 | Integration | Custom => Duration::from_secs(30),
    }
}
