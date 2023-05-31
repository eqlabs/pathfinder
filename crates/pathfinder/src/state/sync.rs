pub mod l1;
pub mod l2;
mod pending;

use anyhow::Context;
use pathfinder_common::{
    BlockHash, BlockNumber, Chain, ChainId, ClassCommitment, ClassHash, ContractNonce,
    ContractRoot, EventCommitment, GasPrice, SequencerAddress, StarknetVersion, StateCommitment,
    StorageCommitment, TransactionCommitment,
};
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use pathfinder_merkle_tree::{
    contract_state::{calculate_contract_state_hash, update_contract_state},
    ClassCommitmentTree, StorageCommitmentTree,
};
use pathfinder_rpc::{
    v02::types::syncing::{self, NumberedBlock, Syncing},
    websocket::types::WebsocketSenders,
    SyncState,
};
use pathfinder_storage::{
    insert_canonical_state_diff,
    types::{CompressedCasmClass, CompressedContract},
    CasmClassTable, ClassCommitmentLeavesTable, ContractCodeTable, ContractsStateTable,
    L1StateTable, RefsTable, StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable,
    StarknetTransactionsTable, Storage,
};
use primitive_types::H160;
use rusqlite::{Connection, Transaction, TransactionBehavior};
use stark_hash::Felt;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::{
    pending::PendingData,
    reply::{
        state_update::DeployedContract, Block, MaybePendingBlock, PendingStateUpdate, StateUpdate,
    },
};

use std::sync::Arc;
use std::{collections::HashMap, future::Future};
use tokio::sync::mpsc;

use crate::state::l2::BlockChain;

/// Implements the main sync loop, where L1 and L2 sync results are combined.
#[allow(clippy::too_many_arguments)]
pub async fn sync<Ethereum, SequencerClient, F1, F2, L1Sync, L2Sync>(
    storage: Storage,
    ethereum: Ethereum,
    chain: Chain,
    chain_id: ChainId,
    core_address: H160,
    sequencer: SequencerClient,
    state: Arc<SyncState>,
    mut l1_sync: L1Sync,
    l2_sync: L2Sync,
    pending_data: PendingData,
    pending_poll_interval: Option<std::time::Duration>,
    block_validation_mode: l2::BlockValidationMode,
    websocket_txs: WebsocketSenders,
    block_cache_size: usize,
) -> anyhow::Result<()>
where
    Ethereum: EthereumApi + Clone,
    SequencerClient: GatewayApi + Clone + Send + Sync + 'static,
    F1: Future<Output = anyhow::Result<()>> + Send + 'static,
    F2: Future<Output = anyhow::Result<()>> + Send + 'static,
    L1Sync: FnMut(mpsc::Sender<EthereumStateUpdate>, Ethereum, Chain, H160) -> F1,
    L2Sync: FnOnce(
            mpsc::Sender<l2::Event>,
            WebsocketSenders,
            SequencerClient,
            Option<(BlockNumber, BlockHash, StateCommitment)>,
            Chain,
            ChainId,
            Option<std::time::Duration>,
            l2::BlockValidationMode,
            BlockChain,
        ) -> F2
        + Copy,
{
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (tx_l1, mut rx_l1) = mpsc::channel(1);
    let (tx_l2, mut rx_l2) = mpsc::channel(1);

    let l2_head = tokio::task::block_in_place(|| -> anyhow::Result<_> {
        let tx = db_conn.transaction()?;
        let l2_head = StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
            .context("Query L2 head from database")?
            .map(|block| (block.number, block.hash, block.state_commmitment));
        Ok(l2_head)
    })?;

    // Start update sync-status process.
    let (starting_block_num, starting_block_hash, _) = l2_head.unwrap_or((
        // Seems a better choice for an invalid block number than 0
        BlockNumber::MAX,
        BlockHash(Felt::ZERO),
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
    let mut l1_handle = tokio::spawn(l1_sync(tx_l1, ethereum.clone(), chain, core_address));

    let latest_blocks = latest_n_blocks(storage.clone(), block_cache_size)
        .await
        .context("Fetching latest blocks from storage")?;
    let block_chain = BlockChain::with_capacity(1_000, latest_blocks);
    let mut l2_handle = tokio::spawn(l2_sync(
        tx_l2,
        websocket_txs.clone(),
        sequencer.clone(),
        l2_head,
        chain,
        chain_id,
        pending_poll_interval,
        block_validation_mode,
        block_chain,
    ));

    let mut last_block_start = std::time::Instant::now();
    let mut block_time_avg = std::time::Duration::ZERO;
    const BLOCK_TIME_WEIGHT: f32 = 0.05;
    /// Delay before restarting L1 or L2 tasks if they fail. This delay helps prevent DoS if these
    /// tasks are crashing.
    #[cfg(not(test))]
    const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::from_secs(60);

    loop {
        tokio::select! {
            l1_event = rx_l1.recv() => match l1_event {
                Some(update) => {
                    l1_update(&mut db_conn, &update).await?;
                    tracing::info!("L1 sync updated to block {}", update.block_number);
                }
                None => {
                    // L1 sync process failed; restart it.
                    match l1_handle.await.context("Join L1 sync process handle")? {
                        Ok(()) => {
                            tracing::error!("L1 sync process terminated without an error.");
                        }
                        Err(e) => {
                            tracing::warn!("L1 sync process terminated with: {:?}", e);
                        }
                    }

                    let (new_tx, new_rx) = mpsc::channel(1);
                    rx_l1 = new_rx;

                    let fut = l1_sync(new_tx, ethereum.clone(), chain, core_address);

                    l1_handle = tokio::spawn(async move {
                        #[cfg(not(test))]
                        tokio::time::sleep(RESET_DELAY_ON_FAILURE).await;
                        fut.await
                    });
                    tracing::info!("L1 sync process restarted.")
                },
            },
            l2_event = rx_l2.recv() => match l2_event {
                Some(l2::Event::Update((block, (tx_comm, ev_comm)), state_update, timings)) => {
                    let block_number = block.block_number;
                    let block_hash = block.block_hash;
                    let storage_updates: usize = state_update.state_diff.storage_diffs.values().map(|storage_diffs| storage_diffs.len()).sum();
                    let update_t = std::time::Instant::now();
                    l2_update(&mut db_conn, *block, tx_comm, ev_comm, *state_update)
                        .await
                        .with_context(|| format!("Update L2 state to {block_number}"))?;
                    // This opens a short window where `pending` overlaps with `latest` in storage. Unfortuantely
                    // there is no easy way of having a transaction over both memory and database. sqlite does support
                    // multi-database transactions, but it does not work for WAL mode.
                    pending_data.clear().await;
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

                    // Give a simple log under INFO level, and a more verbose log
                    // with timing information under DEBUG+ level.
                    //
                    // This should be removed if we have a configurable log level.
                    // See the docs for LevelFilter for more information.
                    match tracing::level_filters::LevelFilter::current().into_level() {
                        None => {}
                        Some(level) if level <= tracing::Level::INFO => {
                            tracing::info!("Updated Starknet state with block {}", block_number)
                        }
                        Some(_) => {
                            tracing::debug!("Updated Starknet state with block {} after {:2}s ({:2}s avg). contracts ({:2}s), {} storage updates ({:2}s). Block downloaded in {:2}s, state diff in {:2}s",
                                block_number,
                                block_time.as_secs_f32(),
                                block_time_avg.as_secs_f32(),
                                timings.class_declaration.as_secs_f32(),
                                storage_updates,
                                update_t.as_secs_f32(),
                                timings.block_download.as_secs_f32(),
                                timings.state_diff_download.as_secs_f32(),
                            );
                        }
                    }
                }
                Some(l2::Event::Reorg(reorg_tail)) => {
                    pending_data.clear().await;

                    l2_reorg(&mut db_conn, reorg_tail)
                        .await
                        .with_context(|| format!("Reorg L2 state to {reorg_tail:?}"))?;

                    let new_head = match reorg_tail {
                        BlockNumber::GENESIS => None,
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
                Some(l2::Event::Pending(block, state_update)) => {
                    download_verify_and_insert_missing_classes(sequencer.clone(), &mut db_conn, &state_update, chain, &block.starknet_version)
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
                    .map(|block| (block.number, block.hash, block.state_commmitment));

                    let (new_tx, new_rx) = mpsc::channel(1);

                    rx_l2 = new_rx;


                    let latest_blocks = latest_n_blocks(storage.clone(), block_cache_size).await.context("Fetching latest blocks from storage")?;
                    let block_chain = BlockChain::with_capacity(1_000, latest_blocks);
                    let fut = l2_sync(new_tx, websocket_txs.clone(), sequencer.clone(), l2_head, chain, chain_id, pending_poll_interval, block_validation_mode, block_chain);

                    l2_handle = tokio::spawn(async move {
                        #[cfg(not(test))]
                        tokio::time::sleep(RESET_DELAY_ON_FAILURE).await;
                        fut.await
                    });
                    tracing::info!("L2 sync process restarted.");
                }
            },
        }
    }
}

async fn latest_n_blocks(
    storage: Storage,
    n: usize,
) -> anyhow::Result<Vec<(BlockNumber, BlockHash, StateCommitment)>> {
    tokio::task::spawn_blocking(move || {
        let mut connection = storage
            .connection()
            .context("Creating database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;

        let mut stmt = tx
            .prepare_cached(
                "SELECT number, hash, root FROM starknet_blocks ORDER BY number DESC LIMIT ?",
            )
            .context("Preparing database statement")?;
        let rows = stmt
            .query_map([n], |row| {
                let number: BlockNumber = row.get(0).unwrap();
                let hash: BlockHash = row.get(1).unwrap();
                let commitment: StateCommitment = row.get(2).unwrap();

                Ok((number, hash, commitment))
            })
            .context("Querying database")?;

        let mut blocks = Vec::new();
        for row in rows {
            blocks.push(row.context("Reading row from database")?);
        }
        // We need to reverse the order here because we want the last `N` blocks in chronological order.
        // Our sql query gives us the last `N` blocks but in reverse order (ORDER BY DESC), so we undo that here.
        blocks.reverse();

        Ok(blocks)
    })
    .await
    .context("Joining database task")?
}

/// Periodically updates sync state with the latest block height.
async fn update_sync_status_latest(
    state: Arc<SyncState>,
    sequencer: impl GatewayApi,
    starting_block_hash: BlockHash,
    starting_block_num: BlockNumber,
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

async fn l1_update(
    connection: &mut Connection,
    update: &EthereumStateUpdate,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        L1StateTable::upsert(&transaction, update).context("Insert update")?;

        let l2_hash = StarknetBlocksTable::get_hash(&transaction, update.block_number.into())?;

        if let Some(l2_hash) = l2_hash {
            if l2_hash == update.block_hash {
                RefsTable::set_l1_l2_head(&transaction, Some(update.block_number))
                    .context("Update L1-L2 head")?;
                tracing::info!(block_number=?update.block_number, "L1/L2 block hash match");
            } else {
                tracing::warn!(block_number=?update.block_number, L1=?update.block_hash, L2=?l2_hash, "L1/L2 block hash mismatch");
                if let Some(matching_block_number) = RefsTable::get_l1_l2_head(&transaction)? {
                    tracing::warn!(block_number=?matching_block_number, "Most recent L1/L2 block hash match")
                }
            }
        }

        transaction.commit().context("Commit database transaction")
    })
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
            state_commmitment: block.state_commitment,
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
            &block.starknet_version,
            new_storage_commitment,
            new_class_commitment,
        )
        .context("Insert block into database")?;

        CanonicalBlocksTable::insert(&transaction, block.block_number, block.block_hash)
            .context("Inserting canonical block into database")?;

        let rpc_state_update: pathfinder_storage::types::StateUpdate = state_update.into();

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
            ContractCodeTable::update_block_number_if_null(
                &transaction,
                class_hash,
                block.block_number,
            )
            .with_context(|| format!("Setting declared_on for class={class_hash:?}"))?;
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

        // Insert state updates
        insert_canonical_state_diff(
            &transaction,
            block.block_number,
            &rpc_state_update.state_diff,
        )
        .context("Insert state update into database")?;

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        let expected_next = l1_l2_head
            .map(|head| head + 1)
            .unwrap_or(BlockNumber::GENESIS);

        if expected_next == starknet_block.number {
            let l1_root =
                L1StateTable::get_state_commitment(&transaction, starknet_block.number.into())
                    .context("Query L1 root")?;
            if l1_root == Some(starknet_block.state_commmitment) {
                RefsTable::set_l1_l2_head(&transaction, Some(starknet_block.number))
                    .context("Update L1-L2 head")?;
            }
        }

        transaction.commit().context("Commit database transaction")
    })
}

async fn l2_reorg(connection: &mut Connection, reorg_tail: BlockNumber) -> anyhow::Result<()> {
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
                    BlockNumber::GENESIS => None,
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
async fn download_verify_and_insert_missing_classes<SequencerClient: GatewayApi>(
    sequencer: SequencerClient,
    connection: &mut Connection,
    state_update: &PendingStateUpdate,
    chain: Chain,
    version: &StarknetVersion,
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
        let class = download_class(&sequencer, class_hash, chain, version.clone()).await?;

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

async fn download_class<SequencerClient: GatewayApi>(
    sequencer: &SequencerClient,
    class_hash: ClassHash,
    chain: Chain,
    version: StarknetVersion,
) -> Result<DownloadedClass, anyhow::Error> {
    use starknet_gateway_types::class_hash::compute_class_hash;

    let definition = sequencer
        .pending_class_by_hash(class_hash)
        .await
        .with_context(|| format!("Downloading class {}", class_hash.0))?;

    tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        let hash = compute_class_hash(&definition).context("Computing class hash")?;

        anyhow::ensure!(
            class_hash == hash.hash(),
            "Class hash mismatch, {} instead of {}",
            hash.hash(),
            class_hash.0
        );

        let mut compressor = zstd::bulk::Compressor::new(10).context("Creating zstd compressor")?;

        use starknet_gateway_types::class_hash::ComputedClassHash;
        match hash {
            ComputedClassHash::Cairo(_) => {
                let definition = compressor
                .compress(&definition)
                .context("Compressing class definition")?;
            let compressed_contract = CompressedContract {
                definition,
                hash: class_hash,
            };
                Ok(DownloadedClass::Cairo(compressed_contract))
            }
            starknet_gateway_types::class_hash::ComputedClassHash::Sierra(hash) => {
                // FIXME(integration reset): work-around for integration containing Sierra classes
                // that are incompatible with production compiler. This will get "fixed" in the future
                // by resetting integration to remove these classes at which point we can revert this.
                //
                // The work-around ignores compilation errors on integration, and instead replaces the
                // casm definition with empty bytes.
                let casm_definition = crate::sierra::compile_to_casm(&definition, &version)
                    .context("Compiling Sierra class");
                let casm_definition = match (casm_definition, chain) {
                    (Ok(casm_definition), _) => casm_definition,
                    (Err(_), Chain::Integration) => {
                        tracing::info!(class_hash=%hash, "Ignored CASM compilation failure integration network");
                        Vec::new()
                    }
                    (Err(e), _) => return Err(e),
                };

                let definition = compressor
                    .compress(&definition)
                    .context("Compressing class definition")?;
                let compressed_contract = CompressedContract {
                    definition,
                    hash: class_hash,
                };

                let casm_definition = compressor
                    .compress(&casm_definition)
                    .context("Compressing CASM definition")?;
                let compressed_casm = pathfinder_storage::types::CompressedCasmClass {
                    definition: casm_definition,
                    hash,
                };

                Ok(DownloadedClass::Sierra(
                    compressed_contract,
                    compressed_casm,
                ))
            }
        }
    }).await.context("Joining class processing task")?
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

#[cfg(test)]
mod tests {
    use super::l2;
    use crate::state;
    use futures::stream::{StreamExt, TryStreamExt};
    use pathfinder_common::{
        BlockHash, BlockId, BlockNumber, BlockTimestamp, CasmHash, Chain, ChainId, ClassCommitment,
        ClassHash, GasPrice, SequencerAddress, StarknetVersion, StateCommitment, StorageCommitment,
    };
    use pathfinder_ethereum::EthereumStateUpdate;
    use pathfinder_rpc::{websocket::types::WebsocketSenders, SyncState};
    use pathfinder_storage::{
        types::{CompressedCasmClass, CompressedContract},
        CasmClassTable, ContractCodeTable, L1StateTable, RefsTable, StarknetBlock,
        StarknetBlocksBlockId, StarknetBlocksTable, Storage,
    };
    use primitive_types::H160;
    use stark_hash::Felt;
    use starknet_gateway_client::GatewayApi;
    use starknet_gateway_types::{error::SequencerError, pending::PendingData, reply};
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;

    #[derive(Debug, Clone)]
    struct FakeTransport;

    #[async_trait::async_trait]
    impl pathfinder_ethereum::EthereumApi for FakeTransport {
        async fn get_starknet_state(
            &self,
            _: &H160,
        ) -> anyhow::Result<pathfinder_ethereum::EthereumStateUpdate> {
            unimplemented!()
        }

        async fn get_chain(&self) -> anyhow::Result<pathfinder_common::EthereumChain> {
            unimplemented!()
        }
    }

    // We need a simple clonable mock here. Satisfies the sync() internals,
    // and is not really called anywhere in the tests except for status updates
    // which we don't test against here.
    #[derive(Debug, Clone)]
    struct FakeSequencer;

    #[async_trait::async_trait]
    impl GatewayApi for FakeSequencer {
        async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
            match block {
                BlockId::Latest => Ok(reply::MaybePendingBlock::Block(BLOCK0.clone())),
                BlockId::Number(_) => Ok(reply::MaybePendingBlock::Block(BLOCK0.clone())),
                _ => unimplemented!(),
            }
        }
    }

    async fn l1_noop(
        _: mpsc::Sender<EthereumStateUpdate>,
        _: FakeTransport,
        _: Chain,
        _: H160,
    ) -> anyhow::Result<()> {
        // Avoid being restarted all the time by the outer sync() loop
        std::future::pending::<()>().await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn l2_noop(
        _: mpsc::Sender<l2::Event>,
        _: WebsocketSenders,
        _: impl GatewayApi,
        _: Option<(BlockNumber, BlockHash, StateCommitment)>,
        _: Chain,
        _: ChainId,
        _: Option<std::time::Duration>,
        _: l2::BlockValidationMode,
        _: l2::BlockChain,
    ) -> anyhow::Result<()> {
        // Avoid being restarted all the time by the outer sync() loop
        std::future::pending::<()>().await;
        Ok(())
    }

    lazy_static::lazy_static! {
        static ref A: Felt = Felt::from_be_slice(&[0xA]).unwrap();
        static ref B: Felt = Felt::from_be_slice(&[0xB]).unwrap();
        static ref STORAGE_COMMITMENT0: StorageCommitment = StorageCommitment::ZERO;
        static ref STORAGE_COMMITMENT1: StorageCommitment = StorageCommitment(Felt::from_be_slice(&[0xC]).unwrap());
        static ref CLASS_COMMITMENT0: ClassCommitment = ClassCommitment::ZERO;
        static ref CLASS_COMMITMENT1: ClassCommitment = ClassCommitment(Felt::from_be_slice(&[0xD]).unwrap());
        static ref STATE_COMMITMENT0: StateCommitment = StateCommitment::calculate(*STORAGE_COMMITMENT0, *CLASS_COMMITMENT0);
        static ref STATE_COMMITMENT1: StateCommitment = StateCommitment::calculate(*STORAGE_COMMITMENT1, *CLASS_COMMITMENT1);

        pub static ref STATE_UPDATE_LOG0: pathfinder_ethereum::EthereumStateUpdate = pathfinder_ethereum::EthereumStateUpdate {
            block_number: BlockNumber::GENESIS,
            block_hash: BlockHash(*A),
            state_root: *STATE_COMMITMENT0,
        };
        pub static ref STATE_UPDATE_LOG1: pathfinder_ethereum::EthereumStateUpdate = pathfinder_ethereum::EthereumStateUpdate {
            block_number: BlockNumber::new_or_panic(1),
            block_hash: BlockHash(*B),
            state_root: *STATE_COMMITMENT1,
        };
        pub static ref BLOCK0: reply::Block = reply::Block {
            block_hash: BlockHash(*A),
            block_number: BlockNumber::GENESIS,
            gas_price: Some(GasPrice::ZERO),
            parent_block_hash: BlockHash(Felt::ZERO),
            sequencer_address: Some(SequencerAddress(Felt::ZERO)),
            state_commitment: *STATE_COMMITMENT0,
            status: reply::Status::AcceptedOnL1,
            timestamp: BlockTimestamp::new_or_panic(0),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: StarknetVersion::default(),
        };
        pub static ref BLOCK1: reply::Block = reply::Block {
            block_hash: BlockHash(*B),
            block_number: BlockNumber::new_or_panic(1),
            gas_price: Some(GasPrice::from(1)),
            parent_block_hash: BlockHash(*A),
            sequencer_address: Some(SequencerAddress(Felt::from_be_bytes([1u8; 32]).unwrap())),
            state_commitment: *STATE_COMMITMENT1,
            status: reply::Status::AcceptedOnL2,
            timestamp: BlockTimestamp::new_or_panic(1),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: StarknetVersion::default(),
        };
        pub static ref STORAGE_BLOCK0: StarknetBlock = StarknetBlock {
            number: BlockNumber::GENESIS,
            hash: BlockHash(*A),
            state_commmitment: *STATE_COMMITMENT0,
            timestamp: BlockTimestamp::new_or_panic(0),
            gas_price: GasPrice::ZERO,
            sequencer_address: SequencerAddress(Felt::ZERO),
            transaction_commitment: None,
            event_commitment: None,
        };
        pub static ref STORAGE_BLOCK1: StarknetBlock = StarknetBlock {
            number: BlockNumber::new_or_panic(1),
            hash: BlockHash(*B),
            state_commmitment: *STATE_COMMITMENT1,
            timestamp: BlockTimestamp::new_or_panic(1),
            gas_price: GasPrice::from(1),
            sequencer_address: SequencerAddress(Felt::from_be_bytes([1u8; 32]).unwrap()),
            transaction_commitment: None,
            event_commitment: None,
        };
        // Causes root to remain unchanged
        pub static ref STATE_UPDATE0: reply::StateUpdate = reply::StateUpdate {
            block_hash: BlockHash(*A),
            new_root: *STATE_COMMITMENT0,
            old_root: *STATE_COMMITMENT0,
            state_diff: reply::state_update::StateDiff{
                storage_diffs: std::collections::HashMap::new(),
                deployed_contracts: vec![],
                old_declared_contracts: vec![],
                nonces: std::collections::HashMap::new(),
                declared_classes: vec![],
                replaced_classes: vec![],
            },
        };
    }

    mod l1_update {
        use primitive_types::H160;

        use super::*;

        async fn with_state(
            state: Vec<(StarknetBlock, StorageCommitment, ClassCommitment)>,
            update: pathfinder_ethereum::EthereumStateUpdate,
        ) -> Option<BlockNumber> {
            let l1 = move |tx: mpsc::Sender<EthereumStateUpdate>, _, _, _| {
                let u = update.clone();
                async move {
                    tx.send(u).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(())
                }
            };

            let chain = Chain::Testnet;
            let chain_id = ChainId::TESTNET;
            let sync_state = Arc::new(SyncState::default());
            let core_address = H160::zero();

            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            let websocket_txs = WebsocketSenders::for_test();

            state
                .into_iter()
                .for_each(|(block, storage_commitment, class_commitment)| {
                    StarknetBlocksTable::insert(
                        &tx,
                        &block,
                        &StarknetVersion::default(),
                        storage_commitment,
                        class_commitment,
                    )
                    .unwrap()
                });

            tx.commit().unwrap();

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                chain,
                chain_id,
                core_address,
                FakeSequencer,
                sync_state.clone(),
                l1,
                l2_noop,
                PendingData::default(),
                None,
                l2::BlockValidationMode::Strict,
                websocket_txs.clone(),
                100,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(300)).await;

            let tx = connection.transaction().unwrap();
            RefsTable::get_l1_l2_head(&tx).unwrap()
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
        async fn no_l2_head() {
            assert_eq!(with_state(vec![], STATE_UPDATE_LOG0.clone()).await, None);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
        async fn l2_head_one_update() {
            assert_eq!(
                with_state(
                    vec![(
                        STORAGE_BLOCK0.clone(),
                        *STORAGE_COMMITMENT0,
                        *CLASS_COMMITMENT0,
                    )],
                    STATE_UPDATE_LOG0.clone(),
                )
                .await,
                Some(BlockNumber::GENESIS),
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_restart() -> Result<(), anyhow::Error> {
        use anyhow::Context;
        let storage = Storage::in_memory().unwrap();

        let (starts_tx, mut starts_rx) = tokio::sync::mpsc::channel(1);
        let websocket_txs = WebsocketSenders::for_test();

        let l1 = move |_, _, _, _| {
            let starts_tx = starts_tx.clone();
            async move {
                // signal we've (re)started
                // This will panic on the third repeat
                //  - the main test task will exit
                //  - this will panic, but test will pass.
                //  - not great, but will get refactored eventually.
                starts_tx
                    .send(())
                    .await
                    .expect("starts_rx should still be alive");
                Ok(())
            }
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            ChainId::TESTNET,
            H160::zero(),
            FakeSequencer,
            Arc::new(SyncState::default()),
            l1,
            l2_noop,
            PendingData::default(),
            None,
            l2::BlockValidationMode::Strict,
            websocket_txs,
            100,
        ));

        let timeout = std::time::Duration::from_secs(1);

        tokio::time::timeout(timeout, starts_rx.recv())
            .await
            .context("l1 sync should had started")?
            .context("l1 closure should not had been dropped yet")?;

        tokio::time::timeout(timeout, starts_rx.recv())
            .await
            .context("l1 sync should had been re-started")?
            .context("l1 closure should not had been dropped yet")?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_update() {
        let sync_state = Arc::new(SyncState::default());
        let websocket_txs = WebsocketSenders::for_test();

        // Incoming L2 update
        let block = || BLOCK0.clone();
        let state_update = || STATE_UPDATE0.clone();
        let timings = l2::Timings {
            block_download: Duration::default(),
            state_diff_download: Duration::default(),
            class_declaration: Duration::default(),
        };

        // A simple L2 sync task
        let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _| async move {
            tx.send(l2::Event::Update(
                (Box::new(block()), Default::default()),
                Box::new(state_update()),
                timings,
            ))
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        let results = [
            // Case 0: no L1 head
            None,
            // Case 1: some L1 head
            Some(STATE_UPDATE_LOG0.clone()),
        ]
        .into_iter()
        .map(|update_log| async {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            if let Some(some_update_log) = update_log {
                L1StateTable::upsert(&tx, &some_update_log).unwrap();
            }

            tx.commit().unwrap();

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                Chain::Testnet,
                ChainId::TESTNET,
                H160::zero(),
                FakeSequencer,
                sync_state.clone(),
                l1_noop,
                l2,
                PendingData::default(),
                None,
                l2::BlockValidationMode::Strict,
                websocket_txs.clone(),
                100,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(100)).await;

            let tx = connection.transaction().unwrap();
            RefsTable::get_l1_l2_head(&tx)
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();

        assert_eq!(
            results,
            vec![
                // Case 0: no L1-L2 head expected
                None,
                // Case 1: some L1-L2 head expected
                Some(BlockNumber::GENESIS),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_reorg() {
        let results = [
            // Case 0: single block in L2, reorg on genesis
            (
                vec![(
                    STORAGE_BLOCK0.clone(),
                    *STORAGE_COMMITMENT0,
                    *CLASS_COMMITMENT0,
                )],
                0,
            ),
            // Case 1: 2 blocks in L2, reorg on block #1
            (
                vec![
                    (
                        STORAGE_BLOCK0.clone(),
                        *STORAGE_COMMITMENT0,
                        *CLASS_COMMITMENT0,
                    ),
                    (
                        STORAGE_BLOCK1.clone(),
                        *STORAGE_COMMITMENT1,
                        *CLASS_COMMITMENT1,
                    ),
                ],
                1,
            ),
        ]
        .into_iter()
        .map(|(updates, reorg_on_block)| async move {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            let websocket_txs = WebsocketSenders::for_test();

            // A simple L2 sync task
            let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _| async move {
                tx.send(l2::Event::Reorg(BlockNumber::new_or_panic(reorg_on_block)))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            };

            RefsTable::set_l1_l2_head(&tx, Some(BlockNumber::new_or_panic(reorg_on_block)))
                .unwrap();
            updates
                .into_iter()
                .for_each(|(block, storage_commitment, class_commitment)| {
                    StarknetBlocksTable::insert(
                        &tx,
                        &block,
                        &StarknetVersion::default(),
                        storage_commitment,
                        class_commitment,
                    )
                    .unwrap()
                });

            tx.commit().unwrap();

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                Chain::Testnet,
                ChainId::TESTNET,
                H160::zero(),
                FakeSequencer,
                Arc::new(SyncState::default()),
                l1_noop,
                l2,
                PendingData::default(),
                None,
                l2::BlockValidationMode::Strict,
                websocket_txs,
                100,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(100)).await;

            let tx = connection.transaction().unwrap();
            let latest_block_number = StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
                .unwrap()
                .map(|s| s.number);
            let head = RefsTable::get_l1_l2_head(&tx).unwrap();
            (head, latest_block_number)
        })
        .collect::<futures::stream::FuturesOrdered<_>>()
        .collect::<Vec<_>>()
        .await;

        assert_eq!(
            results,
            vec![
                // Case 0: no L1-L2 head expected, as we start from genesis
                (None, None),
                // Case 1: some L1-L2 head expected, block #1 removed
                (Some(BlockNumber::GENESIS), Some(BlockNumber::GENESIS)),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_new_cairo_contract() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();
        let websocket_txs = WebsocketSenders::for_test();

        // A simple L2 sync task
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _| async move {
            let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
            tx.send(l2::Event::NewCairoContract(CompressedContract {
                definition: zstd_magic,
                hash: ClassHash(*A),
            }))
            .await
            .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            ChainId::TESTNET,
            H160::zero(),
            FakeSequencer,
            Arc::new(SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
            l2::BlockValidationMode::Strict,
            websocket_txs,
            100,
        ));

        // TODO Find a better way to figure out that the DB update has already been performed
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            ContractCodeTable::exists(&connection, &[ClassHash(*A)]).unwrap(),
            vec![true]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_new_sierra_contract() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();
        let websocket_txs = WebsocketSenders::for_test();

        // A simple L2 sync task
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _| async move {
            let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
            tx.send(l2::Event::NewSierraContract(
                CompressedContract {
                    definition: zstd_magic.clone(),
                    hash: ClassHash(*A),
                },
                CompressedCasmClass {
                    hash: ClassHash(*A),
                    definition: zstd_magic,
                },
                CasmHash(*A),
            ))
            .await
            .unwrap();

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            ChainId::TESTNET,
            H160::zero(),
            FakeSequencer,
            Arc::new(SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
            l2::BlockValidationMode::Strict,
            websocket_txs,
            100,
        ));

        // TODO Find a better way to figure out that the DB update has already been performed
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            ContractCodeTable::exists(&connection, &[ClassHash(*A)]).unwrap(),
            vec![true]
        );
        assert_eq!(
            CasmClassTable::exists(&connection, &[ClassHash(*A)]).unwrap(),
            vec![true]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_restart() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let storage = Storage::in_memory().unwrap();

        static CNT: AtomicUsize = AtomicUsize::new(0);
        let websocket_txs = WebsocketSenders::for_test();

        // A simple L2 sync task
        let l2 = move |_, _, _, _, _, _, _, _, _| async move {
            CNT.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            ChainId::TESTNET,
            H160::zero(),
            FakeSequencer,
            Arc::new(SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
            l2::BlockValidationMode::Strict,
            websocket_txs,
            100,
        ));

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(CNT.load(Ordering::Relaxed) > 1);
    }
}
