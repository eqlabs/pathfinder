mod class;
pub mod l1;
pub mod l2;
mod pending;

use anyhow::Context;
use pathfinder_common::{
    BlockHash, BlockHeader, BlockNumber, CasmHash, Chain, ChainId, ClassCommitment, ClassHash,
    ContractNonce, ContractRoot, EventCommitment, GasPrice, SequencerAddress, StarknetVersion,
    StateCommitment, StorageCommitment, TransactionCommitment,
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
use pathfinder_storage::{Connection, Storage, Transaction, TransactionBehavior};
use primitive_types::H160;
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
use crate::state::sync::class::{download_class, DownloadedClass};

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
            Storage,
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
        let l2_head = tx
            .block_header(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block header from database")?
            .map(|header| (header.number, header.hash, header.state_commitment));

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
        storage.clone(),
    ));

    let mut last_block_start = std::time::Instant::now();
    let mut block_time_avg = std::time::Duration::ZERO;
    const BLOCK_TIME_WEIGHT: f32 = 0.05;
    /// Delay before restarting L1 or L2 tasks if they fail. This delay helps prevent DoS if these
    /// tasks are crashing.
    #[cfg(not(test))]
    const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::from_secs(60);
    #[cfg(test)]
    const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::ZERO;

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
                Some(l2::Event::CairoClass { definition, hash }) => {
                    tokio::task::block_in_place(|| {
                        let tx = db_conn.transaction().context("Creating database transaction")?;
                        tx.insert_cairo_class(hash, &definition).context("Inserting new cairo class")?;
                        tx.commit().context("Committing database transaction")
                    })
                    .with_context(|| {
                        format!("Insert Cairo contract definition with hash: {hash}")
                    })?;

                    tracing::debug!(%hash, "Inserted new Cairo class");
                }
                Some(l2::Event::SierraClass { sierra_definition, sierra_hash, casm_definition, casm_hash }) => {
                    tokio::task::block_in_place(|| {
                        let tx = db_conn.transaction().context("Creating database transaction")?;
                        tx.insert_sierra_class(
                            &sierra_hash,
                            &sierra_definition,
                            &casm_hash,
                            &casm_definition,
                            crate::sierra::COMPILER_VERSION
                        )
                        .context("Inserting sierra class")?;
                        tx.commit().context("Committing database transaction")
                    })
                    .with_context(|| {
                        format!("Insert Sierra contract definition with hash: {sierra_hash}")
                    })?;

                    tracing::debug!(sierra=%sierra_hash, casm=%casm_hash, "Inserted new Sierra class");
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
                        tx.block_header(pathfinder_storage::BlockId::Latest)
                    })
                    .context("Query L2 head from database")?
                    .map(|block| (block.number, block.hash, block.state_commitment));

                    let (new_tx, new_rx) = mpsc::channel(1);

                    rx_l2 = new_rx;


                    let latest_blocks = latest_n_blocks(storage.clone(), block_cache_size).await.context("Fetching latest blocks from storage")?;
                    let block_chain = BlockChain::with_capacity(1_000, latest_blocks);
                    let fut = l2_sync(new_tx, websocket_txs.clone(), sequencer.clone(), l2_head, chain, chain_id, pending_poll_interval, block_validation_mode, block_chain, storage.clone());

                    l2_handle = tokio::spawn(async move {
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

        let mut current = pathfinder_storage::BlockId::Latest;
        let mut blocks = Vec::new();

        for _ in 0..n {
            let header = tx.block_header(current).context("Fetching block header")?;
            let Some(header) = header else {
                break;
            };

            blocks.push((header.number, header.hash, header.state_commitment));

            if header.number == BlockNumber::GENESIS {
                break;
            }
            current = (header.number - 1).into();
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

        transaction
            .upsert_l1_state(update)
            .context("Insert update")?;

        let l2_hash = transaction
            .block_id(update.block_number.into())
            .context("Fetching block hash")?
            .map(|(_, hash)| hash);

        if let Some(l2_hash) = l2_hash {
            if l2_hash == update.block_hash {
                transaction
                    .update_l1_l2_pointer(Some(update.block_number))
                    .context("Updating L1-L2 pointer")?;
                tracing::info!(block=?update.block_number, "Updated L1/L2 match");
            } else {
                tracing::warn!(block_number=?update.block_number, L1=?update.block_hash, L2=?l2_hash, "L1/L2 block hash mismatch");
                if let Some(matching_block_number) = transaction.l1_l2_pointer()? {
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
    transaction_commitment: TransactionCommitment,
    event_commitment: EventCommitment,
    state_update: StateUpdate,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        let (storage_commitment, class_commitment) =
            update_starknet_state(&transaction, &state_update)
                .context("Updating Starknet state")?;
        let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);

        // Ensure that roots match.. what should we do if it doesn't? For now the whole sync process ends..
        anyhow::ensure!(
            state_commitment == block.state_commitment,
            "State root mismatch"
        );

        // Update L2 database. These types shouldn't be options at this level,
        // but for now the unwraps are "safe" in that these should only ever be
        // None for pending queries to the sequencer, but we aren't using those here.
        let header = BlockHeader {
            hash: block.block_hash,
            parent_hash: block.parent_block_hash,
            number: block.block_number,
            timestamp: block.timestamp,
            // Default value for cairo <0.8.2 is 0
            gas_price: block.gas_price.unwrap_or(GasPrice::ZERO),
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(Felt::ZERO)),
            starknet_version: block.starknet_version,
            class_commitment,
            event_commitment,
            state_commitment,
            storage_commitment,
            transaction_commitment,
        };

        transaction
            .insert_block_header(&header)
            .context("Inserting block header into database")?;

        let rpc_state_update: pathfinder_storage::types::StateUpdate = state_update.into();

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
        transaction
            .insert_transaction_data(header.hash, header.number, &transaction_data)
            .context("Insert transaction data into database")?;

        // Insert state updates
        transaction
            .insert_state_diff(block.block_number, &rpc_state_update.state_diff)
            .context("Insert state update into database")?;

        // Track combined L1 and L2 state.
        let l1_l2_head = transaction.l1_l2_pointer().context("Query L1-L2 head")?;
        let expected_next = l1_l2_head
            .map(|head| head + 1)
            .unwrap_or(BlockNumber::GENESIS);

        if expected_next == header.number {
            if let Some(l1_state) = transaction
                .l1_state_at_number(header.number)
                .context("Query L1 state")?
            {
                if l1_state.block_hash == header.hash {
                    transaction
                        .update_l1_l2_pointer(Some(header.number))
                        .context("Update L1-L2 head")?;
                }
            }
        }

        transaction.commit().context("Commit database transaction")
    })
}

async fn l2_reorg(connection: &mut Connection, reorg_tail: BlockNumber) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        let mut head = transaction
            .block_id(pathfinder_storage::BlockId::Latest)
            .context("Quering latest block number")?
            .context("Latest block number is none during reorg")?
            .0;

        // Purge each block one at a time.
        //
        // This is done 1-by-1 to allow sending the reorg'd block data
        // to websocket subscriptions while keeping a constant memory footprint.
        //
        // This is acceptable performance because reorgs are rare and need not be
        // 100% optimal. However a large reorg could cause a massive memory spike
        // which is not acceptable.
        while head >= reorg_tail {
            transaction
                .purge_block(head)
                .with_context(|| format!("Purging block {head} from database"))?;

            // No further blocks to purge if we just purged genesis.
            if head == BlockNumber::GENESIS {
                break;
            }

            head -= 1;
        }

        // Track combined L1 and L2 state.
        let l1_l2_head = transaction.l1_l2_pointer().context("Query L1-L2 head")?;
        if let Some(l1_l2_head) = l1_l2_head {
            if reorg_tail == BlockNumber::GENESIS {
                // If we purged genesis then unset the L1 L2 pointer as well since there
                // are now no blocks remaining.
                transaction
                    .update_l1_l2_pointer(None)
                    .context("Unsetting L1-L2 head")?;
            } else if l1_l2_head >= reorg_tail {
                transaction
                    .update_l1_l2_pointer(Some(reorg_tail - 1))
                    .context("Updating L1-L2 head")?;
            }
        }

        transaction.commit().context("Commit database transaction")
    })
}

fn update_starknet_state(
    transaction: &Transaction<'_>,
    state_update: &StateUpdate,
) -> anyhow::Result<(StorageCommitment, ClassCommitment)> {
    let (storage_commitment, class_commitment) = transaction
        .block_header(pathfinder_storage::BlockId::Latest)
        .context("Querying latest state commitment")?
        .map(|header| (header.storage_commitment, header.class_commitment))
        .unwrap_or((StorageCommitment::ZERO, ClassCommitment::ZERO));

    let mut storage_commitment_tree = StorageCommitmentTree::load(transaction, storage_commitment)
        .context("Loading storage trie")?;

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
    let (new_storage_commitment, nodes) = storage_commitment_tree
        .commit()
        .context("Apply storage commitment tree updates")?;
    let count = transaction
        .insert_storage_trie(new_storage_commitment, &nodes)
        .context("Persisting storage trie")?;
    tracing::trace!(new_nodes=%count, "Storage trie persisted");

    // Add new Sierra classes to class commitment tree.
    let mut class_commitment_tree = ClassCommitmentTree::load(transaction, class_commitment);

    for sierra_class in &state_update.state_diff.declared_classes {
        let leaf_hash = pathfinder_common::calculate_class_commitment_leaf_hash(
            sierra_class.compiled_class_hash,
        );

        transaction
            .insert_class_commitment_leaf(&leaf_hash, &sierra_class.compiled_class_hash)
            .context("Adding class commitment leaf")?;

        class_commitment_tree
            .set(sierra_class.class_hash, leaf_hash)
            .context("Update class commitment tree")?;
    }

    // Apply all class commitment tree changes.
    let (class_commitment, nodes) = class_commitment_tree
        .commit()
        .context("Apply class commitment tree updates")?;
    let count = transaction
        .insert_class_trie(class_commitment, &nodes)
        .context("Persisting class trie")?;
    tracing::trace!(new_nodes=%count, "Class trie persisted");

    Ok((new_storage_commitment, class_commitment))
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
    transaction
        .insert_contract_state(state_hash, class_hash, contract_root, contract_nonce)
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
        transaction.class_definitions_exist(&classes)
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
            DownloadedClass::Cairo { definition, hash } => {
                tokio::task::block_in_place(|| {
                    let transaction =
                        connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    transaction
                        .insert_cairo_class(hash, &definition)
                        .context("Inserting new cairo class")?;
                    transaction.commit()?;
                    anyhow::Result::<()>::Ok(())
                })
                .with_context(|| format!("Insert class definition with hash: {hash}"))?;
            }
            DownloadedClass::Sierra {
                sierra_definition,
                sierra_hash,
                casm_definition,
            } => {
                // NOTE: we _have_ to use the same compiled_class_class hash as returned by the feeder gateway,
                // since that's what has been added to the class commitment tree.
                let casm_hash = state_update
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
                let casm_hash = ClassHash(casm_hash.0);
                tokio::task::block_in_place(|| {
                    let transaction =
                        connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
                    transaction
                        .insert_sierra_class(
                            &sierra_hash,
                            &sierra_definition,
                            &CasmHash(casm_hash.0),
                            &casm_definition,
                            crate::sierra::COMPILER_VERSION,
                        )
                        .context("Inserting sierra class")?;
                    transaction.commit()?;
                    anyhow::Result::<()>::Ok(())
                })
                .with_context(|| format!("Insert class definition with hash: {sierra_hash}"))?;
            }
        }

        tracing::trace!("Inserted new class {}", class_hash.0.to_hex_str());
    }

    Ok(())
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
        felt_bytes, BlockHash, BlockHeader, BlockId, BlockNumber, BlockTimestamp, CasmHash, Chain,
        ChainId, ClassCommitment, ClassHash, GasPrice, SequencerAddress, SierraHash,
        StarknetVersion, StateCommitment, StorageCommitment,
    };
    use pathfinder_ethereum::EthereumStateUpdate;
    use pathfinder_rpc::{websocket::types::WebsocketSenders, SyncState};
    use pathfinder_storage::Storage;
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
        _: Storage,
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
        pub static ref BLOCK_HEADER_0: BlockHeader = BlockHeader::builder()
            .with_state_commitment(*STATE_COMMITMENT0)
            .finalize_with_hash(BlockHash(*A));
        pub static ref BLOCK_HEADER_1: BlockHeader = BLOCK_HEADER_0.child_builder()
            .with_state_commitment(*STATE_COMMITMENT1)
            .with_timestamp(BlockTimestamp::new_or_panic(1))
            .with_gas_price(GasPrice::from(1))
            .with_sequencer_address(SequencerAddress(felt_bytes!(&[1u8; 32])))
            .finalize_with_hash(BlockHash(*B));

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
        use pathfinder_common::BlockHeader;
        use primitive_types::H160;

        use super::*;

        async fn with_state(
            headers: Vec<BlockHeader>,
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

            for header in headers {
                tx.insert_block_header(&header).unwrap();
            }

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
            tx.l1_l2_pointer().unwrap()
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
        async fn no_l2_head() {
            assert_eq!(with_state(vec![], STATE_UPDATE_LOG0.clone()).await, None);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
        async fn l2_head_one_update() {
            assert_eq!(
                with_state(vec![BLOCK_HEADER_0.clone()], STATE_UPDATE_LOG0.clone(),).await,
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
        let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _, _| async move {
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
                tx.upsert_l1_state(&some_update_log).unwrap();
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
            tx.l1_l2_pointer()
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
            (vec![BLOCK_HEADER_0.clone()], 0),
            // Case 1: 2 blocks in L2, reorg on block #1
            (vec![BLOCK_HEADER_0.clone(), BLOCK_HEADER_1.clone()], 1),
        ]
        .into_iter()
        .map(|(headers, reorg_on_block)| async move {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            let websocket_txs = WebsocketSenders::for_test();

            // A simple L2 sync task
            let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _, _| async move {
                tx.send(l2::Event::Reorg(BlockNumber::new_or_panic(reorg_on_block)))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            };

            for header in headers {
                tx.insert_block_header(&header).unwrap();
            }

            tx.update_l1_l2_pointer(Some(BlockNumber::new_or_panic(reorg_on_block)))
                .unwrap();

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
            let latest_block_number = tx
                .block_id(pathfinder_storage::BlockId::Latest)
                .unwrap()
                .map(|x| x.0);
            let head = tx.l1_l2_pointer().unwrap();
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
        let mut connection = storage.connection().unwrap();
        let websocket_txs = WebsocketSenders::for_test();

        // A simple L2 sync task
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _, _| async move {
            tx.send(l2::Event::CairoClass {
                definition: vec![],
                hash: ClassHash(*A),
            })
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

        let tx = connection.transaction().unwrap();
        assert_eq!(
            tx.class_definitions_exist(&[ClassHash(*A)]).unwrap(),
            vec![true]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_new_sierra_contract() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let websocket_txs = WebsocketSenders::for_test();

        // A simple L2 sync task
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _, _, _, _, _, _| async move {
            tx.send(l2::Event::SierraClass {
                sierra_definition: vec![],
                sierra_hash: SierraHash(*A),
                casm_definition: vec![],
                casm_hash: CasmHash(*A),
            })
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

        let tx = connection.transaction().unwrap();
        assert_eq!(
            tx.class_definitions_exist(&[ClassHash(*A)]).unwrap(),
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
        let l2 = move |_, _, _, _, _, _, _, _, _, _| async move {
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
