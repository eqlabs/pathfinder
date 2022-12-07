pub mod l1;
pub mod l2;
mod pending;

use crate::{
    rpc::v01::types::reply::{syncing, syncing::NumberedBlock, Syncing as SyncStatus},
    state::{calculate_contract_state_hash, state_tree::GlobalStateTree, update_contract_state},
};
use anyhow::Context;
use ethers::types::H160;
use pathfinder_common::{
    Chain, ClassHash, ContractNonce, ContractRoot, GasPrice, GlobalRoot, SequencerAddress,
    StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
};
use pathfinder_ethereum::{log::StateUpdateLog, provider::EthereumTransport};
use pathfinder_storage::{
    ContractCodeTable, ContractsStateTable, ContractsTable, L1StateTable, L1TableBlockId,
    RefsTable, StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable,
    StarknetStateUpdatesTable, StarknetTransactionsTable, Storage,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};
use stark_hash::StarkHash;
use starknet_gateway_client::ClientApi;
use starknet_gateway_types::reply::{
    state_update::DeployedContract, Block, MaybePendingBlock, PendingBlock, StateUpdate,
};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

pub struct State {
    pub status: RwLock<SyncStatus>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            status: RwLock::new(SyncStatus::False(false)),
        }
    }
}

struct PendingInner {
    pub block: Arc<PendingBlock>,
    pub state_update: Arc<StateUpdate>,
}

#[derive(Default, Clone)]
pub struct PendingData {
    inner: Arc<RwLock<Option<PendingInner>>>,
}

impl PendingData {
    pub async fn set(&self, block: Arc<PendingBlock>, state_update: Arc<StateUpdate>) {
        *self.inner.write().await = Some(PendingInner {
            block,
            state_update,
        });
    }

    pub async fn clear(&self) {
        *self.inner.write().await = None;
    }

    pub async fn block(&self) -> Option<Arc<PendingBlock>> {
        self.inner
            .read()
            .await
            .as_ref()
            .map(|inner| inner.block.clone())
    }

    pub async fn state_update(&self) -> Option<Arc<StateUpdate>> {
        self.inner
            .read()
            .await
            .as_ref()
            .map(|inner| inner.state_update.clone())
    }

    pub async fn state_update_on_parent_block(
        &self,
    ) -> Option<(StarknetBlockHash, StarknetBlockTimestamp, Arc<StateUpdate>)> {
        let g = self.inner.read().await;
        let inner = g.as_ref()?;

        Some((
            inner.block.parent_hash,
            inner.block.timestamp,
            inner.state_update.clone(),
        ))
    }
}

/// Implements the main sync loop, where L1 and L2 sync results are combined.
#[allow(clippy::too_many_arguments)]
pub async fn sync<Transport, SequencerClient, F1, F2, L1Sync, L2Sync>(
    storage: Storage,
    transport: Transport,
    chain: Chain,
    core_address: H160,
    sequencer: SequencerClient,
    state: Arc<State>,
    mut l1_sync: L1Sync,
    l2_sync: L2Sync,
    pending_data: PendingData,
    pending_poll_interval: Option<std::time::Duration>,
) -> anyhow::Result<()>
where
    Transport: EthereumTransport + Clone,
    SequencerClient: ClientApi + Clone + Send + Sync + 'static,
    F1: Future<Output = anyhow::Result<()>> + Send + 'static,
    F2: Future<Output = anyhow::Result<()>> + Send + 'static,
    L1Sync: FnMut(mpsc::Sender<l1::Event>, Transport, Chain, H160, Option<StateUpdateLog>) -> F1,
    L2Sync: FnOnce(
            mpsc::Sender<l2::Event>,
            SequencerClient,
            Option<(StarknetBlockNumber, StarknetBlockHash, GlobalRoot)>,
            Chain,
            Option<std::time::Duration>,
        ) -> F2
        + Copy,
{
    // TODO: should this be owning a Storage, or just take in a Connection?
    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (tx_l1, mut rx_l1) = mpsc::channel(1);
    let (tx_l2, mut rx_l2) = mpsc::channel(1);

    let (l1_head, l2_head) = tokio::task::block_in_place(|| -> anyhow::Result<_> {
        let tx = db_conn.transaction()?;
        let l1_head = L1StateTable::get(&tx, L1TableBlockId::Latest)
            .context("Query L1 head from database")?;
        let l2_head = StarknetBlocksTable::get(&tx, StarknetBlocksBlockId::Latest)
            .context("Query L2 head from database")?
            .map(|block| (block.number, block.hash, block.root));
        Ok((l1_head, l2_head))
    })?;

    // Start update sync-status process.
    let (starting_block_num, starting_block_hash, _) = l2_head.unwrap_or((
        // Seems a better choice for an invalid block number than 0
        StarknetBlockNumber::MAX,
        StarknetBlockHash(StarkHash::ZERO),
        GlobalRoot(StarkHash::ZERO),
    ));
    let _status_sync = tokio::spawn(update_sync_status_latest(
        Arc::clone(&state),
        sequencer.clone(),
        starting_block_hash,
        starting_block_num,
        chain,
    ));

    // Start L1 and L2 sync processes.
    let mut l1_handle = tokio::spawn(l1_sync(
        tx_l1,
        transport.clone(),
        chain,
        core_address,
        l1_head,
    ));
    let mut l2_handle = tokio::spawn(l2_sync(
        tx_l2,
        sequencer.clone(),
        l2_head,
        chain,
        pending_poll_interval,
    ));

    let mut existed = (0, 0);

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
                Some(l1::Event::Update(updates)) => {
                    let first = updates.first().map(|u| u.block_number.get());
                    let last = updates.last().map(|u| u.block_number.get());

                    l1_update(&mut db_conn, &updates).await.with_context(|| {
                        format!("Update L1 state with blocks {:?}-{:?}", first, last)
                    })?;

                    match updates.as_slice() {
                        [single] => {
                            tracing::info!("L1 sync updated to block {}", single.block_number);
                        }
                        [first, .., last] => {
                            tracing::info!(
                                "L1 sync updated with blocks {} - {}",
                                first.block_number,
                                last.block_number
                            );
                        }
                        _ => {}
                    }
                }
                Some(l1::Event::Reorg(reorg_tail)) => {
                    l1_reorg(&mut db_conn, reorg_tail)
                        .await
                        .with_context(|| format!("Reorg L1 state to block {}", reorg_tail))?;

                    let new_head = match reorg_tail {
                        StarknetBlockNumber::GENESIS => None,
                        other => Some(other - 1),
                    };

                    match new_head {
                        Some(head) => {
                            tracing::info!("L1 reorg occurred, new L1 head is block {}", head)
                        }
                        None => tracing::info!("L1 reorg occurred, new L1 head is genesis"),
                    }
                }
                Some(l1::Event::QueryUpdate(block, tx)) => {
                    let update =
                        tokio::task::block_in_place(|| {
                            let tx = db_conn.transaction()?;
                            L1StateTable::get(&tx, block.into())
                        })
                        .with_context(|| format!("Query L1 state table for block {:?}", block))?;

                    let _ = tx.send(update);

                    tracing::trace!("Query for L1 update for block {}", block);
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
                    let l1_head = tokio::task::block_in_place(|| {
                        let tx = db_conn.transaction()?;
                        L1StateTable::get(&tx, L1TableBlockId::Latest)
                    })
                    .context("Query L1 head from database")?;

                    let (new_tx, new_rx) = mpsc::channel(1);
                    rx_l1 = new_rx;

                    let fut = l1_sync(new_tx, transport.clone(), chain, core_address, l1_head);

                    l1_handle = tokio::spawn(async move {
                        #[cfg(not(test))]
                        tokio::time::sleep(RESET_DELAY_ON_FAILURE).await;
                        fut.await
                    });
                    tracing::info!("L1 sync process restarted.")
                },
            },
            l2_event = rx_l2.recv() => match l2_event {
                Some(l2::Event::Update(block, state_update, timings)) => {
                    pending_data.clear().await;

                    let block_number = block.block_number;
                    let block_hash = block.block_hash;
                    let storage_updates: usize = state_update.state_diff.storage_diffs.iter().map(|(_, storage_diffs)| storage_diffs.len()).sum();
                    let update_t = std::time::Instant::now();
                    l2_update(&mut db_conn, *block, *state_update)
                        .await
                        .with_context(|| format!("Update L2 state to {}", block_number))?;
                    let block_time = last_block_start.elapsed();
                    let update_t = update_t.elapsed();
                    last_block_start = std::time::Instant::now();

                    block_time_avg = block_time_avg.mul_f32(1.0 - BLOCK_TIME_WEIGHT)
                        + block_time.mul_f32(BLOCK_TIME_WEIGHT);

                    // Update sync status
                    match &mut *state.status.write().await {
                        SyncStatus::False(_) => {}
                        SyncStatus::Status(status) => {
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
                            tracing::info!("Updated StarkNet state with block {}", block_number)
                        }
                        Some(_) => {
                            tracing::debug!("Updated StarkNet state with block {} after {:2}s ({:2}s avg). {} ({} new) contracts ({:2}s), {} storage updates ({:2}s). Block downloaded in {:2}s, state diff in {:2}s",
                                block_number,
                                block_time.as_secs_f32(),
                                block_time_avg.as_secs_f32(),
                                existed.0,
                                existed.0 - existed.1,
                                timings.contract_deployment.as_secs_f32(),
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
                        .with_context(|| format!("Reorg L2 state to {:?}", reorg_tail))?;

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
                Some(l2::Event::NewContract(contract)) => {
                    tokio::task::block_in_place(|| {
                        ContractCodeTable::insert_compressed(&db_conn, &contract)
                    })
                    .with_context(|| {
                        format!("Insert contract definition with hash: {:?}", contract.hash)
                    })?;

                    tracing::trace!("Inserted new contract {}", contract.hash.0.to_hex_str());
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
                            format!("Query storage for existance of contracts {:?}", contracts)
                        })?;
                    let count = exists.iter().filter(|b| **b).count();

                    // Fixme: This stat tracking is now incorrect, as these are shared by deploy and declare.
                    //        Overall, quite nasty as is, so should get a proper refactor instead.
                    existed = (contracts.len(), count);

                    let _ = tx.send(exists);

                    tracing::trace!("Query for existence of contracts: {:?}", contracts);
                }
                Some(l2::Event::Pending(block, state_update)) => {
                    let deployed_classes = state_update.state_diff.deployed_contracts.iter().map(|x| x.class_hash);
                    let declared_classes = state_update.state_diff.declared_contracts.iter().cloned();
                    let declared_classes_block = block
                        .transactions
                        .iter()
                        .filter_map(|tx| {
                            use starknet_gateway_types::reply::transaction::Transaction::*;
                            match tx {
                                Declare(tx) => Some(tx.class_hash),
                                Deploy(_) | DeployAccount(_) | Invoke(_) | L1Handler(_) => None,
                            }
                        });
                    let classes = deployed_classes
                        .chain(declared_classes)
                        .chain(declared_classes_block);
                    download_verify_and_insert_missing_classes(sequencer.clone(), &mut db_conn, classes)
                        .await
                        .context("Downloading missing classes for pending block")?;

                    // Collect all potentially new classes.
                    let new_root = tokio::task::block_in_place(|| {
                        // Update state tree to determine new state root, but rollback the changes as we do
                        // not want to persist them.
                        let tx = db_conn
                            .transaction_with_behavior(TransactionBehavior::Immediate)
                            .context("Create database transaction")?;
                        let new_root = update_starknet_state(&tx, &state_update).context("Updating Starknet state")?;
                        tx.rollback()?;
                        anyhow::Result::<GlobalRoot>::Ok(new_root)
                    }).context("Calculate pending state root")?;

                    match new_root == state_update.new_root {
                        true => {
                            pending_data.set(block, state_update).await;
                            tracing::debug!("Updated pending data");
                        }
                        false => {
                            pending_data.clear().await;
                            tracing::error!(
                                head=%state_update.old_root,
                                pending=%state_update.new_root,
                                calculated=%new_root,
                                "Pending state root mismatch"
                            );
                        }
                    }
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

                    let fut = l2_sync(new_tx, sequencer.clone(), l2_head, chain, pending_poll_interval);

                    l2_handle = tokio::spawn(async move {
                        #[cfg(not(test))]
                        tokio::time::sleep(RESET_DELAY_ON_FAILURE).await;
                        fut.await
                    });
                    tracing::info!("L2 sync process restarted.");
                }
            }
        }
    }
}

/// Periodically updates sync state with the latest block height.
async fn update_sync_status_latest(
    state: Arc<State>,
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
                    sync_status @ SyncStatus::False(_) => {
                        *sync_status = SyncStatus::Status(syncing::Status {
                            starting,
                            current: starting,
                            highest: latest,
                        });

                        tracing::debug!(
                            status=%sync_status,
                            "Updated sync status",
                        );
                    }
                    SyncStatus::Status(status) => {
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

async fn l1_update(connection: &mut Connection, updates: &[StateUpdateLog]) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        for update in updates {
            L1StateTable::upsert(&transaction, update).context("Insert update")?;
        }

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        let expected_next = l1_l2_head
            .map(|head| head + 1)
            .unwrap_or(StarknetBlockNumber::GENESIS);

        match updates.first() {
            Some(update) if update.block_number == expected_next => {
                let mut next_head = None;
                for update in updates {
                    let l2_root =
                        StarknetBlocksTable::get(&transaction, update.block_number.into())
                            .context("Query L2 root")?
                            .map(|block| block.root);

                    match l2_root {
                        Some(l2_root) if l2_root == update.global_root => {
                            next_head = Some(update.block_number);
                        }
                        _ => break,
                    }
                }

                if let Some(next_head) = next_head {
                    RefsTable::set_l1_l2_head(&transaction, Some(next_head))
                        .context("Update L1-L2 head")?;
                }
            }
            _ => {}
        }

        transaction.commit().context("Commit database transaction")
    })
}

async fn l1_reorg(
    connection: &mut Connection,
    reorg_tail: StarknetBlockNumber,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        L1StateTable::reorg(&transaction, reorg_tail).context("Delete L1 state from database")?;

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

/// Returns the new [GlobalRoot] after the update.
async fn l2_update(
    connection: &mut Connection,
    block: Block,
    state_update: StateUpdate,
) -> anyhow::Result<()> {
    use pathfinder_storage::CanonicalBlocksTable;

    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        let new_root = update_starknet_state(&transaction, &state_update)
            .context("Updating Starknet state")?;

        // Ensure that roots match.. what should we do if it doesn't? For now the whole sync process ends..
        anyhow::ensure!(new_root == block.state_root, "State root mismatch");

        // Update L2 database. These types shouldn't be options at this level,
        // but for now the unwraps are "safe" in that these should only ever be
        // None for pending queries to the sequencer, but we aren't using those here.
        let starknet_block = StarknetBlock {
            number: block.block_number,
            hash: block.block_hash,
            root: block.state_root,
            timestamp: block.timestamp,
            // Default value for cairo <0.8.2 is 0
            gas_price: block.gas_price.unwrap_or(GasPrice::ZERO),
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(StarkHash::ZERO)),
        };
        StarknetBlocksTable::insert(
            &transaction,
            &starknet_block,
            block.starknet_version.as_deref(),
        )
        .context("Insert block into database")?;

        let rpc_state_update = state_update.into();
        StarknetStateUpdatesTable::insert(&transaction, block.block_hash, &rpc_state_update)
            .context("Insert state update into database")?;

        CanonicalBlocksTable::insert(&transaction, block.block_number, block.block_hash)
            .context("Inserting canonical block into database")?;

        for class in rpc_state_update.state_diff.declared_contracts {
            ContractCodeTable::update_declared_on_if_null(
                &transaction,
                class.class_hash,
                block.block_hash,
            )
            .with_context(|| format!("Setting declared_on for class={:?}", class.class_hash))?;
        }
        for class in rpc_state_update.state_diff.deployed_contracts {
            ContractCodeTable::update_declared_on_if_null(
                &transaction,
                class.class_hash,
                block.block_hash,
            )
            .with_context(|| format!("Setting declared_on for class={:?}", class.class_hash))?;
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

        // Track combined L1 and L2 state.
        let l1_l2_head = RefsTable::get_l1_l2_head(&transaction).context("Query L1-L2 head")?;
        let expected_next = l1_l2_head
            .map(|head| head + 1)
            .unwrap_or(StarknetBlockNumber::GENESIS);

        if expected_next == starknet_block.number {
            let l1_root = L1StateTable::get_root(&transaction, starknet_block.number.into())
                .context("Query L1 root")?;
            if l1_root == Some(starknet_block.root) {
                RefsTable::set_l1_l2_head(&transaction, Some(starknet_block.number))
                    .context("Update L1-L2 head")?;
            }
        }

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

        // TODO: clean up state tree's as well...

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
) -> anyhow::Result<GlobalRoot> {
    let global_root = StarknetBlocksTable::get(transaction, StarknetBlocksBlockId::Latest)
        .context("Query latest state root")?
        .map(|block| block.root)
        .unwrap_or(GlobalRoot(StarkHash::ZERO));
    let mut global_tree =
        GlobalStateTree::load(transaction, global_root).context("Loading global state tree")?;

    for contract in &state_update.state_diff.deployed_contracts {
        deploy_contract(transaction, &mut global_tree, contract).context("Deploying contract")?;
    }

    // Copied so we can mutate the map. This lets us remove used nonces from the list.
    let mut nonces = state_update.state_diff.nonces.clone();

    // Apply contract storage updates.
    for (contract_address, updates) in &state_update.state_diff.storage_diffs {
        // Remove the nonce so we don't update it again in the next stage.
        let nonce = nonces.remove(contract_address);

        let contract_state_hash =
            update_contract_state(*contract_address, updates, nonce, &global_tree, transaction)
                .context("Update contract state")?;

        // Update the global state tree.
        global_tree
            .set(*contract_address, contract_state_hash)
            .context("Updating global state tree")?;
    }

    // Apply all remaining nonces (without storage updates).
    for (contract_address, nonce) in nonces {
        let contract_state_hash = update_contract_state(
            contract_address,
            &[],
            Some(nonce),
            &global_tree,
            transaction,
        )
        .context("Update contract nonce")?;

        // Update the global state tree.
        global_tree
            .set(contract_address, contract_state_hash)
            .context("Updating global state tree")?;
    }

    // Apply all global tree changes.
    global_tree
        .apply()
        .context("Apply global state tree updates")
}

fn deploy_contract(
    transaction: &Transaction<'_>,
    global_tree: &mut GlobalStateTree<'_, '_>,
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
    global_tree
        .set(contract.address, state_hash)
        .context("Adding deployed contract to global state tree")?;
    ContractsStateTable::upsert(
        transaction,
        state_hash,
        class_hash,
        contract_root,
        contract_nonce,
    )
    .context("Insert constract state hash into contracts state table")?;
    ContractsTable::upsert(transaction, contract.address, class_hash)
        .context("Inserting class hash into contracts table")
}

/// Downloads and inserts class definitions for any classes in the
/// list which are not already present in the database.
async fn download_verify_and_insert_missing_classes<
    SequencerClient: ClientApi,
    ClassIter: Iterator<Item = ClassHash>,
>(
    sequencer: SequencerClient,
    connection: &mut Connection,
    classes: ClassIter,
) -> anyhow::Result<()> {
    use starknet_gateway_types::class_hash::extract_abi_code_hash;

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
    .with_context(|| format!("Query storage for existance of classes {:?}", classes))?;
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
        let definition = sequencer
            .class_by_hash(class_hash)
            .await
            .with_context(|| format!("Downloading class {}", class_hash.0))?;

        // Parse the contract definition for ABI, code and calculate the class hash. This can
        // be expensive, so perform in a blocking task.
        let extract = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let (abi, bytecode, hash) = extract_abi_code_hash(&definition)?;
            Ok((definition, abi, bytecode, hash))
        });
        let (definition, abi, bytecode, hash) = extract
            .await
            .context("Parse class definition and compute hash")??;

        // Sanity check.
        anyhow::ensure!(
            class_hash == hash,
            "Class hash mismatch, {} instead of {}",
            hash.0,
            class_hash.0
        );

        let compress = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            let mut compressor =
                zstd::bulk::Compressor::new(10).context("Create zstd compressor")?;

            let abi = compressor.compress(&abi).context("Compress ABI")?;
            let bytecode = compressor
                .compress(&bytecode)
                .context("Compress bytecode")?;
            let definition = compressor
                .compress(&definition)
                .context("Compress definition")?;

            Ok((abi, bytecode, definition))
        });
        let (abi, bytecode, definition) = compress.await.context("Compress class")??;
        let compressed = pathfinder_storage::types::CompressedContract {
            abi,
            bytecode,
            definition,
            hash,
        };

        tokio::task::block_in_place(|| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ContractCodeTable::insert_compressed(&transaction, &compressed)?;
            transaction.commit()?;
            anyhow::Result::<()>::Ok(())
        })
        .with_context(|| format!("Insert class definition with hash: {:?}", compressed.hash))?;

        tracing::trace!("Inserted new class {}", compressed.hash.0.to_hex_str());
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
    use super::{l1, l2};
    use crate::state::{self, sync::PendingData};
    use ethers::types::H256;
    use futures::stream::{StreamExt, TryStreamExt};
    use pathfinder_common::{
        BlockId, CallParam, Chain, ClassHash, ConstructorParam, ContractAddress,
        ContractAddressSalt, EntryPoint, EthereumBlockHash, EthereumBlockNumber, EthereumChain,
        EthereumLogIndex, EthereumTransactionHash, EthereumTransactionIndex, Fee, GasPrice,
        GlobalRoot, SequencerAddress, StarknetBlockHash, StarknetBlockNumber,
        StarknetBlockTimestamp, StarknetTransactionHash, StorageAddress, StorageValue,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_storage::{
        types::CompressedContract, ContractCodeTable, L1StateTable, L1TableBlockId, RefsTable,
        StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable, Storage,
    };
    use stark_hash::StarkHash;
    use starknet_gateway_client::ClientApi;
    use starknet_gateway_types::{
        error::SequencerError,
        reply,
        request::{add_transaction::ContractDefinition, BlockHashOrTag},
    };
    use std::{sync::Arc, time::Duration};
    use tokio::sync::mpsc;

    #[derive(Debug, Clone)]
    struct FakeTransport;

    #[async_trait::async_trait]
    impl pathfinder_ethereum::provider::EthereumTransport for FakeTransport {
        async fn block(
            &self,
            _: ethers::types::BlockId,
        ) -> anyhow::Result<Option<ethers::types::Block<H256>>> {
            unimplemented!()
        }

        async fn block_number(&self) -> anyhow::Result<u64> {
            unimplemented!()
        }

        async fn chain(&self) -> anyhow::Result<EthereumChain> {
            unimplemented!()
        }

        async fn logs(
            &self,
            _: ethers::types::Filter,
        ) -> std::result::Result<Vec<ethers::types::Log>, pathfinder_ethereum::provider::LogsError>
        {
            unimplemented!()
        }

        async fn transaction(
            &self,
            _: ethers::types::TxHash,
        ) -> anyhow::Result<Option<ethers::types::Transaction>> {
            unimplemented!()
        }

        async fn gas_price(&self) -> anyhow::Result<ethers::types::U256> {
            unimplemented!()
        }
    }

    // We need a simple clonable mock here. Satisfies the sync() internals,
    // and is not really called anywhere in the tests except for status updates
    // which we don't test against here.
    #[derive(Debug, Clone)]
    struct FakeSequencer;

    #[async_trait::async_trait]
    impl ClientApi for FakeSequencer {
        async fn block(&self, block: BlockId) -> Result<reply::MaybePendingBlock, SequencerError> {
            match block {
                BlockId::Number(_) => Ok(reply::MaybePendingBlock::Block(BLOCK0.clone())),
                _ => unimplemented!(),
            }
        }

        async fn full_contract(&self, _: ContractAddress) -> Result<bytes::Bytes, SequencerError> {
            unimplemented!()
        }

        async fn class_by_hash(&self, _: ClassHash) -> Result<bytes::Bytes, SequencerError> {
            unimplemented!()
        }

        async fn class_hash_at(&self, _: ContractAddress) -> Result<ClassHash, SequencerError> {
            unimplemented!()
        }

        async fn storage(
            &self,
            _: ContractAddress,
            _: StorageAddress,
            _: BlockHashOrTag,
        ) -> Result<StorageValue, SequencerError> {
            unimplemented!()
        }

        async fn transaction(
            &self,
            _: StarknetTransactionHash,
        ) -> Result<reply::Transaction, SequencerError> {
            unimplemented!()
        }

        async fn transaction_status(
            &self,
            _: StarknetTransactionHash,
        ) -> Result<reply::TransactionStatus, SequencerError> {
            unimplemented!()
        }

        async fn state_update(&self, _: BlockId) -> Result<reply::StateUpdate, SequencerError> {
            unimplemented!()
        }

        async fn eth_contract_addresses(
            &self,
        ) -> Result<reply::EthContractAddresses, SequencerError> {
            unimplemented!()
        }

        async fn add_invoke_transaction(
            &self,
            _: TransactionVersion,
            _: Fee,
            _: Vec<TransactionSignatureElem>,
            _: Option<TransactionNonce>,
            _: ContractAddress,
            _: Option<EntryPoint>,
            _: Vec<CallParam>,
        ) -> Result<reply::add_transaction::InvokeResponse, SequencerError> {
            unimplemented!()
        }

        async fn add_declare_transaction(
            &self,
            _: TransactionVersion,
            _: Fee,
            _: Vec<TransactionSignatureElem>,
            _: TransactionNonce,
            _: ContractDefinition,
            _: ContractAddress,
            _: Option<String>,
        ) -> Result<reply::add_transaction::DeclareResponse, SequencerError> {
            unimplemented!()
        }

        async fn add_deploy_transaction(
            &self,
            _: TransactionVersion,
            _: ContractAddressSalt,
            _: Vec<ConstructorParam>,
            _: ContractDefinition,
            _: Option<String>,
        ) -> Result<reply::add_transaction::DeployResponse, SequencerError> {
            unimplemented!()
        }

        async fn add_deploy_account(
            &self,
            _: TransactionVersion,
            _: Fee,
            _: Vec<TransactionSignatureElem>,
            _: TransactionNonce,
            _: ContractAddressSalt,
            _: ClassHash,
            _: Vec<CallParam>,
        ) -> Result<reply::add_transaction::DeployAccountResponse, SequencerError> {
            unimplemented!()
        }
    }

    async fn l1_noop(
        _: mpsc::Sender<l1::Event>,
        _: FakeTransport,
        _: Chain,
        _: ethers::types::H160,
        _: Option<pathfinder_ethereum::log::StateUpdateLog>,
    ) -> anyhow::Result<()> {
        // Avoid being restarted all the time by the outer sync() loop
        std::future::pending::<()>().await;
        Ok(())
    }

    async fn l2_noop(
        _: mpsc::Sender<l2::Event>,
        _: impl ClientApi,
        _: Option<(StarknetBlockNumber, StarknetBlockHash, GlobalRoot)>,
        _: Chain,
        _: Option<std::time::Duration>,
    ) -> anyhow::Result<()> {
        // Avoid being restarted all the time by the outer sync() loop
        std::future::pending::<()>().await;
        Ok(())
    }

    lazy_static::lazy_static! {
        static ref A: StarkHash = StarkHash::from_be_slice(&[0xA]).unwrap();
        static ref B: StarkHash = StarkHash::from_be_slice(&[0xB]).unwrap();
        static ref ETH_ORIG: pathfinder_ethereum::EthOrigin = pathfinder_ethereum::EthOrigin {
            block: pathfinder_ethereum::BlockOrigin {
                hash: EthereumBlockHash(H256::zero()),
                number: EthereumBlockNumber(0),
            },
            log_index: EthereumLogIndex(0),
            transaction: pathfinder_ethereum::TransactionOrigin {
                hash: EthereumTransactionHash(H256::zero()),
                index: EthereumTransactionIndex(0),
            },
        };
        pub static ref STATE_UPDATE_LOG0: pathfinder_ethereum::log::StateUpdateLog = pathfinder_ethereum::log::StateUpdateLog {
            block_number: StarknetBlockNumber::GENESIS,
            // State update actually doesn't change the state hence 0 root
            global_root: GlobalRoot(StarkHash::ZERO),
            origin: ETH_ORIG.clone(),
        };
        pub static ref STATE_UPDATE_LOG1: pathfinder_ethereum::log::StateUpdateLog = pathfinder_ethereum::log::StateUpdateLog {
            block_number: StarknetBlockNumber::new_or_panic(1),
            global_root: GlobalRoot(*B),
            origin: ETH_ORIG.clone(),
        };
        pub static ref BLOCK0: reply::Block = reply::Block {
            block_hash: StarknetBlockHash(*A),
            block_number: StarknetBlockNumber::GENESIS,
            gas_price: Some(GasPrice::ZERO),
            parent_block_hash: StarknetBlockHash(StarkHash::ZERO),
            sequencer_address: Some(SequencerAddress(StarkHash::ZERO)),
            state_root: GlobalRoot(StarkHash::ZERO),
            status: reply::Status::AcceptedOnL1,
            timestamp: StarknetBlockTimestamp::new_or_panic(0),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: None,
        };
        pub static ref BLOCK1: reply::Block = reply::Block {
            block_hash: StarknetBlockHash(*B),
            block_number: StarknetBlockNumber::new_or_panic(1),
            gas_price: Some(GasPrice::from(1)),
            parent_block_hash: StarknetBlockHash(*A),
            sequencer_address: Some(SequencerAddress(StarkHash::from_be_bytes([1u8; 32]).unwrap())),
            state_root: GlobalRoot(*B),
            status: reply::Status::AcceptedOnL2,
            timestamp: StarknetBlockTimestamp::new_or_panic(1),
            transaction_receipts: vec![],
            transactions: vec![],
            starknet_version: None,
        };
        pub static ref STORAGE_BLOCK0: StarknetBlock = StarknetBlock {
            number: StarknetBlockNumber::GENESIS,
            hash: StarknetBlockHash(*A),
            root: GlobalRoot(StarkHash::ZERO),
            timestamp: StarknetBlockTimestamp::new_or_panic(0),
            gas_price: GasPrice::ZERO,
            sequencer_address: SequencerAddress(StarkHash::ZERO),
        };
        pub static ref STORAGE_BLOCK1: StarknetBlock = StarknetBlock {
            number: StarknetBlockNumber::new_or_panic(1),
            hash: StarknetBlockHash(*B),
            root: GlobalRoot(*B),
            timestamp: StarknetBlockTimestamp::new_or_panic(1),
            gas_price: GasPrice::from(1),
            sequencer_address: SequencerAddress(StarkHash::from_be_bytes([1u8; 32]).unwrap()),
        };
        // Causes root to remain 0
        pub static ref STATE_UPDATE0: reply::StateUpdate = reply::StateUpdate {
            block_hash: Some(StarknetBlockHash(*A)),
            new_root: GlobalRoot(StarkHash::ZERO),
            old_root: GlobalRoot(StarkHash::ZERO),
            state_diff: reply::state_update::StateDiff{
                storage_diffs: std::collections::HashMap::new(),
                deployed_contracts: vec![],
                declared_contracts: vec![],
                nonces: std::collections::HashMap::new(),
            },
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_update() {
        let chain = Chain::Testnet;
        let sync_state = Arc::new(state::SyncState::default());
        let core_address = pathfinder_ethereum::contract::TESTNET_ADDRESSES.core;

        lazy_static::lazy_static! {
            static ref UPDATES: Arc<tokio::sync::RwLock<Vec<Vec<pathfinder_ethereum::log::StateUpdateLog>>>> =
            Arc::new(tokio::sync::RwLock::new(vec![
                vec![STATE_UPDATE_LOG0.clone(), STATE_UPDATE_LOG1.clone()],
                vec![STATE_UPDATE_LOG0.clone()],
                vec![STATE_UPDATE_LOG0.clone()],
            ]));
        }

        // A simple L1 sync task
        let l1 = |tx: mpsc::Sender<l1::Event>, _, _, _, _| async move {
            let mut update = UPDATES.write().await;
            if let Some(some_update) = update.pop() {
                tx.send(l1::Event::Update(some_update)).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(())
        };

        let results = [
            // Case 0: no L2 head
            None,
            // Case 1: some L2 head
            Some(vec![STORAGE_BLOCK0.clone()]),
            // Case 2: some L2 head, update contains more than one item
            Some(vec![STORAGE_BLOCK0.clone(), STORAGE_BLOCK1.clone()]),
        ]
        .into_iter()
        .map(|blocks| async {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            blocks
                .iter()
                .flatten()
                .for_each(|block| StarknetBlocksTable::insert(&tx, block, None).unwrap());

            tx.commit().unwrap();
            drop(blocks);

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                chain,
                core_address,
                FakeSequencer,
                sync_state.clone(),
                l1,
                l2_noop,
                PendingData::default(),
                None,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(300)).await;

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
                Some(StarknetBlockNumber::GENESIS),
                // Case 2: some L1-L2 head expected
                Some(StarknetBlockNumber::new_or_panic(1)),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_reorg() {
        let results = [
            // Case 0: single block in L1, reorg on genesis
            (vec![STATE_UPDATE_LOG0.clone()], 0),
            // Case 1: 2 blocks in L1, reorg on block #1
            (
                vec![STATE_UPDATE_LOG0.clone(), STATE_UPDATE_LOG1.clone()],
                1,
            ),
        ]
        .into_iter()
        .map(|(updates, reorg_on_block)| async move {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            // A simple L1 sync task
            let l1 = move |tx: mpsc::Sender<l1::Event>, _, _, _, _| async move {
                tx.send(l1::Event::Reorg(StarknetBlockNumber::new_or_panic(
                    reorg_on_block,
                )))
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            };

            RefsTable::set_l1_l2_head(&tx, Some(StarknetBlockNumber::new_or_panic(reorg_on_block)))
                .unwrap();
            updates
                .into_iter()
                .for_each(|update| L1StateTable::upsert(&tx, &update).unwrap());

            tx.commit().unwrap();

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                Chain::Testnet,
                pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
                FakeSequencer,
                Arc::new(state::SyncState::default()),
                l1,
                l2_noop,
                PendingData::default(),
                None,
            ));

            // TODO Find a better way to figure out that the DB update has already been performed
            tokio::time::sleep(Duration::from_millis(10)).await;

            let tx = connection.transaction().unwrap();

            let latest_block_number = L1StateTable::get(&tx, L1TableBlockId::Latest)
                .unwrap()
                .map(|s| s.block_number);
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
                (
                    Some(StarknetBlockNumber::GENESIS),
                    Some(StarknetBlockNumber::GENESIS)
                ),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_query_update() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        // This is what we're asking for
        L1StateTable::upsert(&tx, &STATE_UPDATE_LOG0).unwrap();

        tx.commit().unwrap();

        // A simple L1 sync task which does the request and checks he result
        let l1 = |tx: mpsc::Sender<l1::Event>, _, _, _, _| async move {
            let (tx1, rx1) =
                tokio::sync::oneshot::channel::<Option<pathfinder_ethereum::log::StateUpdateLog>>();

            tx.send(l1::Event::QueryUpdate(StarknetBlockNumber::GENESIS, tx1))
                .await
                .unwrap();

            // Check the result straight away ¯\_(ツ)_/¯
            assert_eq!(rx1.await.unwrap().unwrap(), *STATE_UPDATE_LOG0);

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1,
            l2_noop,
            PendingData::default(),
            None,
        ));

        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l1_restart() -> Result<(), anyhow::Error> {
        use anyhow::Context;
        let storage = Storage::in_memory().unwrap();

        let (starts_tx, mut starts_rx) = tokio::sync::mpsc::channel(1);

        let l1 = move |_, _, _, _, _| {
            let starts_tx = starts_tx.clone();
            async move {
                // signal we've (re)started
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
            pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1,
            l2_noop,
            PendingData::default(),
            None,
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
        let chain = Chain::Testnet;
        let sync_state = Arc::new(state::SyncState::default());

        // Incoming L2 update
        let block = || BLOCK0.clone();
        let state_update = || STATE_UPDATE0.clone();
        let timings = l2::Timings {
            block_download: Duration::default(),
            state_diff_download: Duration::default(),
            contract_deployment: Duration::default(),
            class_declaration: Duration::default(),
        };

        // A simple L2 sync task
        let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _, _| async move {
            tx.send(l2::Event::Update(
                Box::new(block()),
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
                chain,
                pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
                FakeSequencer,
                sync_state.clone(),
                l1_noop,
                l2,
                PendingData::default(),
                None,
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
                Some(StarknetBlockNumber::GENESIS),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_reorg() {
        let results = [
            // Case 0: single block in L2, reorg on genesis
            (vec![STORAGE_BLOCK0.clone()], 0),
            // Case 1: 2 blocks in L2, reorg on block #1
            (vec![STORAGE_BLOCK0.clone(), STORAGE_BLOCK1.clone()], 1),
        ]
        .into_iter()
        .map(|(updates, reorg_on_block)| async move {
            let storage = Storage::in_memory().unwrap();
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();

            // A simple L2 sync task
            let l2 = move |tx: mpsc::Sender<l2::Event>, _, _, _, _| async move {
                tx.send(l2::Event::Reorg(StarknetBlockNumber::new_or_panic(
                    reorg_on_block,
                )))
                .await
                .unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok(())
            };

            RefsTable::set_l1_l2_head(&tx, Some(StarknetBlockNumber::new_or_panic(reorg_on_block)))
                .unwrap();
            updates
                .into_iter()
                .for_each(|block| StarknetBlocksTable::insert(&tx, &block, None).unwrap());

            tx.commit().unwrap();

            // UUT
            let _jh = tokio::spawn(state::sync(
                storage.clone(),
                FakeTransport,
                Chain::Testnet,
                pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
                FakeSequencer,
                Arc::new(state::SyncState::default()),
                l1_noop,
                l2,
                PendingData::default(),
                None,
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
                (
                    Some(StarknetBlockNumber::GENESIS),
                    Some(StarknetBlockNumber::GENESIS)
                ),
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_new_contract() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();

        // A simple L2 sync task
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _| async move {
            let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];
            tx.send(l2::Event::NewContract(CompressedContract {
                abi: zstd_magic.clone(),
                bytecode: zstd_magic.clone(),
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
            pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
        ));

        // TODO Find a better way to figure out that the DB update has already been performed
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(
            ContractCodeTable::exists(&connection, &[ClassHash(*A)]).unwrap(),
            vec![true]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_query_hash() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        // This is what we're asking for
        StarknetBlocksTable::insert(&tx, &STORAGE_BLOCK0, None).unwrap();

        // A simple L2 sync task which does the request and checks he result
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _| async move {
            let (tx1, rx1) = tokio::sync::oneshot::channel();

            tx.send(l2::Event::QueryBlock(StarknetBlockNumber::GENESIS, tx1))
                .await
                .unwrap();

            // Check the result straight away ¯\_(ツ)_/¯
            let result = rx1.await.unwrap().unwrap();
            assert_eq!(result, (STORAGE_BLOCK0.hash, STORAGE_BLOCK0.root));

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_query_contract_existance() {
        let storage = Storage::in_memory().unwrap();
        let connection = storage.connection().unwrap();
        let zstd_magic = vec![0x28, 0xb5, 0x2f, 0xfd];

        // This is what we're asking for
        ContractCodeTable::insert_compressed(
            &connection,
            &CompressedContract {
                abi: zstd_magic.clone(),
                bytecode: zstd_magic.clone(),
                definition: zstd_magic,
                hash: ClassHash(*A),
            },
        )
        .unwrap();

        // A simple L2 sync task which does the request and checks he result
        let l2 = |tx: mpsc::Sender<l2::Event>, _, _, _, _| async move {
            let (tx1, rx1) = tokio::sync::oneshot::channel::<Vec<bool>>();

            tx.send(l2::Event::QueryContractExistance(vec![ClassHash(*A)], tx1))
                .await
                .unwrap();

            // Check the result straight away ¯\_(ツ)_/¯
            assert_eq!(rx1.await.unwrap(), vec![true]);

            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn l2_restart() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let storage = Storage::in_memory().unwrap();

        static CNT: AtomicUsize = AtomicUsize::new(0);

        // A simple L2 sync task
        let l2 = move |_, _, _, _, _| async move {
            CNT.fetch_add(1, Ordering::Relaxed);
            Ok(())
        };

        // UUT
        let _jh = tokio::spawn(state::sync(
            storage,
            FakeTransport,
            Chain::Testnet,
            pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
            FakeSequencer,
            Arc::new(state::SyncState::default()),
            l1_noop,
            l2,
            PendingData::default(),
            None,
        ));

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(CNT.load(Ordering::Relaxed) > 1);
    }
}
