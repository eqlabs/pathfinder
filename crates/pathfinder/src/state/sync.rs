mod class;
pub mod l1;
pub mod l2;
mod pending;
pub mod revert;

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use pathfinder_common::prelude::*;
use pathfinder_common::state_update::StateUpdateRef;
use pathfinder_common::{
    BlockCommitmentSignature,
    Chain,
    PublicKey,
    ReceiptCommitment,
    StateDiffCommitment,
};
use pathfinder_crypto::Felt;
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use pathfinder_merkle_tree::contract_state::update_contract_state;
use pathfinder_merkle_tree::{ClassCommitmentTree, StorageCommitmentTree};
use pathfinder_rpc::v02::types::syncing::{self, NumberedBlock, Syncing};
use pathfinder_rpc::{Notifications, PendingData, Reorg, SyncState, TopicBroadcasters};
use pathfinder_storage::{Connection, Storage, Transaction, TransactionBehavior};
use primitive_types::H160;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply::{Block, PendingBlock};
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::watch::Sender as WatchSender;

use crate::state::l1::L1SyncContext;
use crate::state::l2::{BlockChain, L2SyncContext};

/// Delay before restarting L1 or L2 tasks if they fail. This delay helps
/// prevent DoS if these tasks are crashing.
#[cfg(not(test))]
pub const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::from_secs(60);
#[cfg(test)]
pub const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::ZERO;

#[derive(Debug)]
pub enum SyncEvent {
    L1Update(EthereumStateUpdate),
    /// New L2 [block update](StateUpdate) found.
    Block(
        (
            Box<Block>,
            (TransactionCommitment, EventCommitment, ReceiptCommitment),
        ),
        Box<StateUpdate>,
        Box<BlockCommitmentSignature>,
        Box<StateDiffCommitment>,
        l2::Timings,
    ),
    /// An L2 reorg was detected, contains the reorg-tail which
    /// indicates the oldest block which is now invalid
    /// i.e. reorg-tail + 1 should be the new head.
    Reorg(BlockNumber),
    /// A new unique L2 Cairo 0.x class was found.
    CairoClass {
        definition: Vec<u8>,
        hash: ClassHash,
    },
    /// A new unique L2 Cairo 1.x class was found.
    SierraClass {
        sierra_definition: Vec<u8>,
        sierra_hash: SierraHash,
        casm_definition: Vec<u8>,
        casm_hash: CasmHash,
    },
    /// A new L2 pending update was polled.
    Pending((Arc<PendingBlock>, Arc<StateUpdate>)),
}

pub struct SyncContext<G, E> {
    pub storage: Storage,
    pub ethereum: E,
    pub chain: Chain,
    pub chain_id: ChainId,
    pub core_address: H160,
    pub sequencer: G,
    pub state: Arc<SyncState>,
    pub head_poll_interval: Duration,
    pub l1_poll_interval: Duration,
    pub pending_data: WatchSender<PendingData>,
    pub block_validation_mode: l2::BlockValidationMode,
    pub websocket_txs: Option<TopicBroadcasters>,
    pub notifications: Notifications,
    pub block_cache_size: usize,
    pub restart_delay: Duration,
    pub verify_tree_hashes: bool,
    pub gossiper: Gossiper,
    pub sequencer_public_key: PublicKey,
    pub fetch_concurrency: std::num::NonZeroUsize,
    pub fetch_casm_from_fgw: bool,
}

impl<G, E> From<&SyncContext<G, E>> for L1SyncContext<E>
where
    E: Clone,
{
    fn from(value: &SyncContext<G, E>) -> Self {
        Self {
            ethereum: value.ethereum.clone(),
            chain: value.chain,
            core_address: value.core_address,
            poll_interval: value.l1_poll_interval,
        }
    }
}

impl<G, E> From<&SyncContext<G, E>> for L2SyncContext<G>
where
    G: Clone,
{
    fn from(value: &SyncContext<G, E>) -> Self {
        Self {
            sequencer: value.sequencer.clone(),
            chain: value.chain,
            chain_id: value.chain_id,
            block_validation_mode: value.block_validation_mode,
            storage: value.storage.clone(),
            sequencer_public_key: value.sequencer_public_key,
            fetch_concurrency: value.fetch_concurrency,
            fetch_casm_from_fgw: value.fetch_casm_from_fgw,
        }
    }
}

#[derive(Debug, Default)]
pub struct Gossiper {
    #[cfg(feature = "p2p")]
    p2p_client: Option<p2p::client::peer_agnostic::Client>,
}

impl Gossiper {
    #[cfg(feature = "p2p")]
    pub fn new(p2p_client: p2p::client::peer_agnostic::Client) -> Self {
        Self {
            p2p_client: Some(p2p_client),
        }
    }

    async fn propagate_head(&self, _block_number: BlockNumber, _block_hash: BlockHash) {
        #[cfg(feature = "p2p")]
        {
            use p2p_proto::common::{BlockId, Hash};

            if let Some(p2p_client) = &self.p2p_client {
                _ = p2p_client
                    .propagate_new_head(BlockId {
                        number: _block_number.get(),
                        hash: Hash(_block_hash.0),
                    })
                    .await
                    .map_err(|error| tracing::warn!(%error, "Propagating head failed"));
            }
        }
    }
}

/// Implements the main sync loop, where L1 and L2 sync results are combined.
pub async fn sync<Ethereum, SequencerClient, F1, F2, L1Sync, L2Sync>(
    context: SyncContext<SequencerClient, Ethereum>,
    mut l1_sync: L1Sync,
    l2_sync: L2Sync,
) -> anyhow::Result<()>
where
    Ethereum: EthereumApi + Clone + Send + 'static,
    SequencerClient: GatewayApi + Clone + Send + Sync + 'static,
    F1: Future<Output = anyhow::Result<()>> + Send + 'static,
    F2: Future<Output = anyhow::Result<()>> + Send + 'static,
    L1Sync: FnMut(mpsc::Sender<SyncEvent>, L1SyncContext<Ethereum>) -> F1,
    L2Sync: FnOnce(
            mpsc::Sender<SyncEvent>,
            L2SyncContext<SequencerClient>,
            Option<(BlockNumber, BlockHash, StateCommitment)>,
            BlockChain,
            tokio::sync::watch::Receiver<(BlockNumber, BlockHash)>,
        ) -> F2
        + Copy,
{
    let l1_context = L1SyncContext::from(&context);
    let l2_context = L2SyncContext::from(&context);

    let SyncContext {
        storage,
        ethereum: _,
        chain: _,
        chain_id: _,
        core_address: _,
        sequencer,
        state,
        head_poll_interval,
        l1_poll_interval: _,
        pending_data,
        block_validation_mode: _,
        websocket_txs,
        notifications,
        block_cache_size,
        restart_delay,
        verify_tree_hashes: _,
        gossiper,
        sequencer_public_key: _,
        fetch_concurrency: _,
        fetch_casm_from_fgw,
    } = context;

    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (event_sender, event_receiver) = mpsc::channel(8);

    // Get the latest block from the database
    let l2_head = tokio::task::block_in_place(|| -> anyhow::Result<_> {
        let tx = db_conn.transaction()?;
        let l2_head = tx
            .block_header(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block header from database")?
            .map(|header| (header.number, header.hash, header.state_commitment));

        Ok(l2_head)
    })?;

    // Get the latest block from the sequencer
    let gateway_latest = sequencer
        .head()
        .await
        .context("Fetching latest block from gateway")?;

    // Keep polling the sequencer for the latest block
    let (tx_latest, rx_latest) = tokio::sync::watch::channel(gateway_latest);
    let mut latest_handle = tokio::spawn(l2::poll_latest(
        sequencer.clone(),
        head_poll_interval,
        tx_latest,
    ));

    // Start update sync-status process.
    let (starting_block_num, starting_block_hash, _) = l2_head.unwrap_or((
        // Seems a better choice for an invalid block number than 0
        BlockNumber::MAX,
        BlockHash(Felt::ZERO),
        StateCommitment(Felt::ZERO),
    ));
    let _status_sync = tokio::spawn(update_sync_status_latest(
        Arc::clone(&state),
        starting_block_hash,
        starting_block_num,
        rx_latest.clone(),
        gossiper,
    ));

    // Start L1 producer task. Clone the event sender so that the channel remains
    // open even if the producer task fails.
    let mut l1_handle = tokio::spawn(l1_sync(event_sender.clone(), l1_context.clone()));

    // Fetch latest blocks from storage
    let latest_blocks = latest_n_blocks(&mut db_conn, block_cache_size)
        .await
        .context("Fetching latest blocks from storage")?;
    let block_chain = BlockChain::with_capacity(1_000, latest_blocks);

    // Start L2 producer task. Clone the event sender so that the channel remains
    // open even if the producer task fails.
    let mut l2_handle = tokio::spawn(l2_sync(
        event_sender.clone(),
        l2_context.clone(),
        l2_head,
        block_chain,
        rx_latest.clone(),
    ));

    let (current_num, current_hash, _) = l2_head.unwrap_or_default();
    let (tx_current, rx_current) = tokio::sync::watch::channel((current_num, current_hash));
    let consumer_context = ConsumerContext {
        storage: storage.clone(),
        state,
        pending_data,
        verify_tree_hashes: context.verify_tree_hashes,
        websocket_txs,
        notifications,
    };
    let mut consumer_handle = tokio::spawn(consumer(event_receiver, consumer_context, tx_current));

    let mut pending_handle = tokio::spawn(pending::poll_pending(
        event_sender.clone(),
        sequencer.clone(),
        Duration::from_secs(2),
        storage.clone(),
        rx_latest.clone(),
        rx_current.clone(),
        fetch_casm_from_fgw,
    ));

    loop {
        tokio::select! {
            _ = &mut pending_handle => {
                tracing::error!("Pending tracking task ended unexpectedly");

                pending_handle = tokio::spawn(pending::poll_pending(
                    event_sender.clone(),
                    sequencer.clone(),
                    Duration::from_secs(2),
                    storage.clone(),
                    rx_latest.clone(),
                    rx_current.clone(),
                    fetch_casm_from_fgw,
                ));
            },
            _ = &mut latest_handle => {
                tracing::error!("Tracking chain tip task ended unexpectedly");
                tracing::debug!("Shutting down other tasks");

                l1_handle.abort();
                l2_handle.abort();
                consumer_handle.abort();
                pending_handle.abort();

                _ = l1_handle.await;
                _ = l2_handle.await;
                _ = consumer_handle.await;
                _ = pending_handle.await;

                anyhow::bail!("Sync process terminated");
            },
            l1_producer_result = &mut l1_handle => {
                match l1_producer_result.context("Join L1 sync process handle")? {
                    Ok(()) => {
                        tracing::error!("L1 sync process terminated without an error.");
                    }
                    Err(e) => {
                        tracing::warn!("L1 sync process terminated with: {e:?}");
                    }
                }

                let fut = l1_sync(event_sender.clone(), l1_context.clone());
                l1_handle = tokio::spawn(async move {
                    tokio::time::sleep(RESET_DELAY_ON_FAILURE).await;
                    fut.await
                });
            },
            l2_producer_result = &mut l2_handle => {
                // L2 sync process failed; restart it.
                match l2_producer_result.context("Join L2 sync process handle")? {
                    Ok(()) => {
                        tracing::error!("L2 sync process terminated without an error.");
                    }
                    Err(e) => {
                        tracing::warn!("L2 sync process terminated with: {e:?}");
                    }
                }

                let l2_head = tokio::task::block_in_place(|| {
                    let tx = db_conn.transaction()?;
                    tx.block_header(pathfinder_storage::BlockId::Latest)
                })
                .context("Query L2 head from database")?
                .map(|block| (block.number, block.hash, block.state_commitment));

                let latest_blocks = latest_n_blocks(&mut db_conn, block_cache_size).await.context("Fetching latest blocks from storage")?;
                let block_chain = BlockChain::with_capacity(1_000, latest_blocks);
                let fut = l2_sync(event_sender.clone(), l2_context.clone(), l2_head, block_chain, rx_latest.clone());

                l2_handle = tokio::spawn(async move {
                    tokio::time::sleep(restart_delay).await;
                    fut.await
                });
                tracing::info!("L2 sync process restarted.");
            },
            consumer_result = &mut consumer_handle => {
                match consumer_result {
                    Ok(Ok(())) => {
                        tracing::debug!("Sync consumer task exited gracefully");
                    },
                    Ok(Err(e)) => {
                        tracing::error!(reason=?e, "Sync consumer task terminated with an error");
                    }
                    Err(e) if e.is_cancelled() => {
                        tracing::debug!("Sync consumer task cancelled successfully");
                    },
                    Err(panic) => {
                        tracing::error!(%panic, "Sync consumer task panic'd");
                    }
                }

                // Shutdown the other processes.
                tracing::debug!("Shutting down L1 and L2 sync producer tasks");
                l1_handle.abort();
                l2_handle.abort();
                pending_handle.abort();
                latest_handle.abort();

                match l1_handle.await {
                    Ok(Ok(())) => {
                        tracing::debug!("L1 sync task exited gracefully");
                    },
                    Ok(Err(e)) => {
                        tracing::error!(reason=?e, "L1 sync task terminated with an error");
                    }
                    Err(e) if e.is_cancelled() => {
                        tracing::debug!("L1 sync task cancelled successfully");
                    },
                    Err(panic) => {
                        tracing::error!(%panic, "L1 sync task panic'd");
                    }
                }

                match l2_handle.await {
                    Ok(Ok(())) => {
                        tracing::debug!("L2 sync task exited gracefully");
                    },
                    Ok(Err(e)) => {
                        tracing::error!(reason=?e, "L2 sync task terminated with an error");
                    }
                    Err(e) if e.is_cancelled() => {
                        tracing::debug!("L2 sync task cancelled successfully");
                    },
                    Err(panic) => {
                        tracing::error!(%panic, "L2 sync task panic'd");
                    }
                }

                match latest_handle.await {
                    Ok(()) => {
                        tracing::debug!("Latest polling task exited gracefully");
                    },
                    Err(e) if e.is_cancelled() => {
                        tracing::debug!("Latest polling task cancelled successfully");
                    },
                    Err(panic) => {
                        tracing::error!(%panic, "Latest polling task panic'd");
                    }
                }

                _ = pending_handle.await;

                anyhow::bail!("Sync process terminated");
            }
        }
    }
}

struct ConsumerContext {
    pub storage: Storage,
    pub state: Arc<SyncState>,
    pub pending_data: WatchSender<PendingData>,
    pub verify_tree_hashes: bool,
    pub websocket_txs: Option<TopicBroadcasters>,
    pub notifications: Notifications,
}

async fn consumer(
    mut events: Receiver<SyncEvent>,
    context: ConsumerContext,
    current: tokio::sync::watch::Sender<(BlockNumber, BlockHash)>,
) -> anyhow::Result<()> {
    let ConsumerContext {
        storage,
        state,
        pending_data,
        verify_tree_hashes,
        mut websocket_txs,
        mut notifications,
    } = context;

    let mut last_block_start = std::time::Instant::now();
    let mut block_time_avg = std::time::Duration::ZERO;
    const BLOCK_TIME_WEIGHT: f32 = 0.05;

    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    let (mut latest_timestamp, mut next_number) = tokio::task::block_in_place(|| {
        let tx = db_conn
            .transaction()
            .context("Creating database transaction")?;
        let latest = tx
            .block_header(pathfinder_storage::BlockId::Latest)
            .context("Fetching latest block header")?
            .map(|b| (b.timestamp, b.number + 1))
            .unwrap_or_default();

        anyhow::Ok(latest)
    })
    .context("Fetching latest block time")?;

    while let Some(event) = events.recv().await {
        use SyncEvent::*;
        match event {
            L1Update(update) => {
                tracing::trace!("Updating L1 sync to block {}", update.block_number);
                l1_update(&mut db_conn, &update).await?;
                tracing::info!("L1 sync updated to block {}", update.block_number);
            }
            Block(
                (block, (tx_comm, ev_comm, rc_comm)),
                state_update,
                signature,
                state_diff_commitment,
                timings,
            ) => {
                tracing::trace!("Updating L2 state to block {}", block.block_number);
                if block.block_number < next_number {
                    tracing::debug!("Ignoring duplicate block {}", block.block_number);
                    continue;
                }

                let block_number = block.block_number;
                let block_hash = block.block_hash;
                let block_timestamp = block.timestamp;
                let storage_updates: usize = state_update
                    .contract_updates
                    .iter()
                    .map(|x| x.1.storage.len())
                    .sum();
                let update_t = std::time::Instant::now();
                l2_update(
                    &mut db_conn,
                    *block,
                    tx_comm,
                    rc_comm,
                    ev_comm,
                    *state_update,
                    *signature,
                    *state_diff_commitment,
                    verify_tree_hashes,
                    storage.clone(),
                    &mut websocket_txs,
                    &mut notifications,
                )
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

                        metrics::gauge!("current_block", block_number.get() as f64);

                        if status.highest.number <= block_number {
                            status.highest = status.current;
                            metrics::gauge!("highest_block", block_number.get() as f64);
                        }
                    }
                }

                _ = current.send((block_number, block_hash));

                let now_timestamp = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
                let latency = now_timestamp.saturating_sub(block_timestamp.get());

                let download_time = (timings.block_download
                    + timings.class_declaration
                    + timings.signature_download)
                    .as_secs_f64();

                metrics::gauge!("block_download", download_time);
                metrics::gauge!("block_processing", update_t.as_secs_f64());
                metrics::histogram!("block_processing_duration_seconds", update_t);
                metrics::gauge!("block_latency", latency as f64);
                metrics::gauge!(
                    "block_time",
                    (block_timestamp.get() - latest_timestamp.get()) as f64
                );
                latest_timestamp = block_timestamp;
                next_number += 1;

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
                        tracing::debug!(
                            "Updated Starknet state with block {} after {:2}s ({:2}s avg). \
                             contracts ({:2}s), {} storage updates ({:2}s). Block downloaded in \
                             {:2}s, signature in {:2}s",
                            block_number,
                            block_time.as_secs_f32(),
                            block_time_avg.as_secs_f32(),
                            timings.class_declaration.as_secs_f32(),
                            storage_updates,
                            update_t.as_secs_f32(),
                            timings.block_download.as_secs_f32(),
                            timings.signature_download.as_secs_f32(),
                        );
                    }
                }
            }
            Reorg(reorg_tail) => {
                tracing::trace!("Reorg L2 state to block {}", reorg_tail);
                l2_reorg(&mut db_conn, reorg_tail, &mut notifications)
                    .await
                    .with_context(|| format!("Reorg L2 state to {reorg_tail:?}"))?;

                next_number = reorg_tail;

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
            CairoClass { definition, hash } => {
                tracing::trace!("Inserting new Cairo class with hash: {hash}");
                tokio::task::block_in_place(|| {
                    let tx = db_conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .context("Creating database transaction")?;
                    tx.insert_cairo_class(hash, &definition)
                        .context("Inserting new cairo class")?;
                    tx.commit().context("Committing database transaction")
                })
                .with_context(|| format!("Insert Cairo contract definition with hash: {hash}"))?;

                tracing::debug!(%hash, "Inserted new Cairo class");
            }
            SierraClass {
                sierra_definition,
                sierra_hash,
                casm_definition,
                casm_hash,
            } => {
                tracing::trace!("Inserting new Sierra class with hash: {sierra_hash}");
                tokio::task::block_in_place(|| {
                    let tx = db_conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)
                        .context("Creating database transaction")?;
                    tx.insert_sierra_class(
                        &sierra_hash,
                        &sierra_definition,
                        &casm_hash,
                        &casm_definition,
                    )
                    .context("Inserting sierra class")?;
                    tx.commit().context("Committing database transaction")
                })
                .with_context(|| {
                    format!("Insert Sierra contract definition with hash: {sierra_hash}")
                })?;

                tracing::debug!(sierra=%sierra_hash, casm=%casm_hash, "Inserted new Sierra class");
            }
            Pending(pending) => {
                tracing::trace!("Updating pending data");
                let (number, hash) = tokio::task::block_in_place(|| {
                    let tx = db_conn
                        .transaction()
                        .context("Creating database transaction")?;
                    let latest = tx
                        .block_id(pathfinder_storage::BlockId::Latest)
                        .context("Fetching latest block hash")?
                        .unwrap_or_default();

                    anyhow::Ok(latest)
                })
                .context("Fetching latest block hash")?;

                if pending.0.parent_hash == hash {
                    let data = PendingData {
                        block: pending.0,
                        state_update: pending.1,
                        number: number + 1,
                    };
                    pending_data.send_replace(data);
                    tracing::debug!("Updated pending data");
                }
            }
        }
    }

    Ok(())
}

async fn latest_n_blocks(
    connection: &mut Connection,
    n: usize,
) -> anyhow::Result<Vec<(BlockNumber, BlockHash, StateCommitment)>> {
    tokio::task::block_in_place(|| {
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

        // We need to reverse the order here because we want the last `N` blocks in
        // chronological order. Our sql query gives us the last `N` blocks but
        // in reverse order (ORDER BY DESC), so we undo that here.
        blocks.reverse();

        Ok(blocks)
    })
}

/// Periodically updates sync state with the latest block height.
///
/// If feature `p2p` is enabled and node type is `proxy`
/// propagates latest head after every change or otherwise every 2 minutes.
async fn update_sync_status_latest(
    state: Arc<SyncState>,
    starting_block_hash: BlockHash,
    starting_block_num: BlockNumber,
    mut latest: tokio::sync::watch::Receiver<(BlockNumber, BlockHash)>,
    gossiper: Gossiper,
) {
    let starting = NumberedBlock::from((starting_block_hash, starting_block_num));

    let mut last_propagated = Instant::now();
    let mut latest_hash = BlockHash::default();

    loop {
        let Ok((number, hash)) = latest
            .wait_for(|(_, hash)| hash != &latest_hash)
            .await
            .as_deref()
            .copied()
        else {
            break;
        };

        latest_hash = hash;
        let latest = NumberedBlock::from((hash, number));
        match &mut *state.status.write().await {
            sync_status @ Syncing::False(_) => {
                *sync_status = Syncing::Status(syncing::Status {
                    starting,
                    current: starting,
                    highest: latest,
                });

                metrics::gauge!("current_block", starting.number.get() as f64);
                metrics::gauge!("highest_block", latest.number.get() as f64);

                propagate_head(&gossiper, &mut last_propagated, latest).await;

                tracing::debug!(
                    status=%sync_status,
                    "Updated sync status",
                );
            }
            Syncing::Status(status) => {
                if status.highest.hash != latest.hash {
                    status.highest = latest;

                    metrics::gauge!("highest_block", latest.number.get() as f64);

                    propagate_head(&gossiper, &mut last_propagated, latest).await;

                    tracing::debug!(
                        %status,
                        "Updated sync status",
                    );
                }
            }
        }

        // duplicate_cache_time for gossipsub defaults to 1 minute
        if last_propagated.elapsed() > Duration::from_secs(120) {
            propagate_head(&gossiper, &mut last_propagated, latest).await;
        }
    }

    tracing::info!("Channel closed, exiting latest poll task");
}

async fn propagate_head(gossiper: &Gossiper, last_propagated: &mut Instant, head: NumberedBlock) {
    _ = gossiper.propagate_head(head.number, head.hash).await;
    *last_propagated = Instant::now();
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
            .block_hash(update.block_number.into())
            .context("Fetching block hash")?;

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

        transaction
            .commit()
            .context("Commit database transaction")?;

        Ok(())
    })
}

/// Returns the new [StateCommitment] after the update.
#[allow(clippy::too_many_arguments)]
async fn l2_update(
    connection: &mut Connection,
    block: Block,
    transaction_commitment: TransactionCommitment,
    receipt_commitment: ReceiptCommitment,
    event_commitment: EventCommitment,
    state_update: StateUpdate,
    signature: BlockCommitmentSignature,
    state_diff_commitment: StateDiffCommitment,
    verify_tree_hashes: bool,
    // we need this so that we can create extra read-only transactions for
    // parallel contract state updates
    storage: Storage,
    websocket_txs: &mut Option<TopicBroadcasters>,
    notifications: &mut Notifications,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;
        let (storage_commitment, class_commitment) = update_starknet_state(
            &transaction,
            (&state_update).into(),
            verify_tree_hashes,
            block.block_number,
            storage,
        )
        .context("Updating Starknet state")?;
        let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);

        // Ensure that roots match.. what should we do if it doesn't? For now the whole
        // sync process ends..
        anyhow::ensure!(
            state_commitment == block.state_commitment,
            "State root mismatch"
        );

        let transaction_count = block.transactions.len();
        let event_count = block
            .transaction_receipts
            .iter()
            .map(|(_, events)| events.len())
            .sum();

        // Update L2 database. These types shouldn't be options at this level,
        // but for now the unwraps are "safe" in that these should only ever be
        // None for pending queries to the sequencer, but we aren't using those here.
        let header = BlockHeader {
            hash: block.block_hash,
            parent_hash: block.parent_block_hash,
            number: block.block_number,
            timestamp: block.timestamp,
            // Default value for cairo <0.8.2 is 0
            eth_l1_gas_price: block.l1_gas_price.price_in_wei,
            // Default value for Starknet <0.13.0 is zero
            strk_l1_gas_price: block.l1_gas_price.price_in_fri,
            // Default value for Starknet <0.13.1 is zero
            eth_l1_data_gas_price: block.l1_data_gas_price.price_in_wei,
            // Default value for Starknet <0.13.1 is zero
            strk_l1_data_gas_price: block.l1_data_gas_price.price_in_fri,
            eth_l2_gas_price: GasPrice(0), // TODO: Fix when we get l2_gas_price in the gateway
            strk_l2_gas_price: GasPrice(0), // TODO: Fix when we get l2_gas_price in the gateway
            sequencer_address: block
                .sequencer_address
                .unwrap_or(SequencerAddress(Felt::ZERO)),
            starknet_version: block.starknet_version,
            class_commitment,
            event_commitment,
            state_commitment,
            storage_commitment,
            transaction_commitment,
            transaction_count,
            event_count,
            l1_da_mode: block.l1_da_mode.into(),
            receipt_commitment,
            state_diff_commitment,
            state_diff_length: state_update.state_diff_length(),
        };

        transaction
            .insert_block_header(&header)
            .context("Inserting block header into database")?;

        // Insert the transactions.
        anyhow::ensure!(
            block.transactions.len() == block.transaction_receipts.len(),
            "Transactions and receipts mismatch. There were {} transactions and {} receipts.",
            block.transactions.len(),
            block.transaction_receipts.len()
        );
        let (transactions_data, events_data): (Vec<_>, Vec<_>) = block
            .transactions
            .iter()
            .cloned()
            .zip(block.transaction_receipts.iter().cloned())
            .map(|(tx, (receipt, events))| ((tx, receipt), events))
            .unzip();

        transaction
            .insert_transaction_data(header.number, &transactions_data, Some(&events_data))
            .context("Insert transaction data into database")?;

        // Insert state updates
        transaction
            .insert_state_update(block.block_number, &state_update)
            .context("Insert state update into database")?;

        // Insert signature
        transaction
            .insert_signature(block.block_number, &signature)
            .context("Insert signature into database")?;

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

        transaction
            .commit()
            .context("Commit database transaction")?;

        if let Some(sender) = websocket_txs {
            if let Err(e) = sender.new_head.send_if_receiving(header.clone().into()) {
                tracing::error!(error=?e, "Failed to send header over websocket broadcaster.");
                // Disable websocket entirely so that the closed channel doesn't spam this
                // error. It is unlikely that any error here wouldn't simply repeat
                // indefinitely.
                *websocket_txs = None;
                return Ok(());
            }
            if sender.l2_blocks.receiver_count() > 0 {
                if let Err(e) = sender.l2_blocks.send(block.clone().into()) {
                    tracing::error!(error=?e, "Failed to send block over websocket broadcaster.");
                    *websocket_txs = None;
                    return Ok(());
                }
            }
        }

        notifications
            .block_headers
            .send(header.into())
            // Ignore errors in case nobody is listening. New listeners may subscribe in the
            // future.
            .ok();
        notifications
            .l2_blocks
            .send(block.into())
            // Ignore errors in case nobody is listening. New listeners may subscribe in the
            // future.
            .ok();

        Ok(())
    })?;

    Ok(())
}

async fn l2_reorg(
    connection: &mut Connection,
    reorg_tail: BlockNumber,
    notifications: &mut Notifications,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        let mut head = transaction
            .block_id(pathfinder_storage::BlockId::Latest)
            .context("Querying latest block number")?
            .context("Latest block number is none during reorg")?
            .0;

        let reorg_tail_hash = transaction
            .block_hash(reorg_tail.into())
            .context("Fetching first block hash")?
            .context("Expected first block hash to exist")?;
        let head_hash = transaction
            .block_hash(head.into())
            .context("Fetching last block hash")?
            .context("Expected last block hash to exist")?;

        transaction
            .increment_reorg_counter()
            .context("Incrementing reorg counter")?;

        // Roll back Merkle trie updates.
        //
        // If we're rolling back genesis then there will be no blocks left so state will
        // be empty.
        if let Some(target_block) = reorg_tail.parent() {
            let target_header = transaction
                .block_header(target_block.into())
                .context("Fetching target block header")?
                .context("Expected target header to exist")?;
            revert::revert_starknet_state(&transaction, head, target_block, target_header)?;
        }

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

        transaction
            .commit()
            .context("Commit database transaction")?;

        notifications
            .reorgs
            .send(
                Reorg {
                    first_block_number: reorg_tail,
                    first_block_hash: reorg_tail_hash,
                    last_block_number: head,
                    last_block_hash: head_hash,
                }
                .into(),
            )
            // Ignore errors in case nobody is listening. New listeners may subscribe in the
            // future.
            .ok();

        Ok(())
    })
}

pub fn update_starknet_state(
    transaction: &Transaction<'_>,
    state_update: StateUpdateRef<'_>,
    verify_hashes: bool,
    block: BlockNumber,
    // we need this so that we can create extra read-only transactions for
    // parallel contract state updates
    storage: Storage,
) -> anyhow::Result<(StorageCommitment, ClassCommitment)> {
    use rayon::prelude::*;

    let mut storage_commitment_tree = match block.parent() {
        Some(parent) => StorageCommitmentTree::load(transaction, parent)
            .context("Loading storage commitment tree")?,
        None => StorageCommitmentTree::empty(transaction),
    }
    .with_verify_hashes(verify_hashes);

    let (send, recv) = std::sync::mpsc::channel();

    rayon::scope(|s| {
        s.spawn(|_| {
            let result: Result<Vec<_>, _> = state_update
                .contract_updates
                .par_iter()
                .map_init(
                    || storage.clone().connection(),
                    |connection, (contract_address, update)| {
                        let connection = match connection {
                            Ok(connection) => connection,
                            Err(e) => anyhow::bail!(
                                "Failed to create database connection in rayon thread: {}",
                                e
                            ),
                        };
                        let transaction = connection.transaction()?;
                        update_contract_state(
                            **contract_address,
                            update.storage,
                            *update.nonce,
                            update.class.as_ref().map(|x| x.class_hash()),
                            &transaction,
                            verify_hashes,
                            block,
                        )
                    },
                )
                .collect();
            let _ = send.send(result);
        })
    });

    let contract_update_results = recv.recv().context("Panic on rayon thread")??;

    for contract_update_result in contract_update_results.into_iter() {
        storage_commitment_tree
            .set(
                contract_update_result.contract_address,
                contract_update_result.state_hash,
            )
            .context("Updating storage commitment tree")?;
        contract_update_result
            .insert(block, transaction)
            .context("Inserting contract update result")?;
    }

    for (contract, update) in state_update.system_contract_updates {
        let update_result = update_contract_state(
            *contract,
            update.storage,
            None,
            None,
            transaction,
            verify_hashes,
            block,
        )
        .context("Update system contract state")?;

        storage_commitment_tree
            .set(*contract, update_result.state_hash)
            .context("Updating system contract storage commitment tree")?;

        update_result
            .insert(block, transaction)
            .context("Persisting system contract trie updates")?;
    }

    // Apply storage commitment tree changes.
    let (storage_commitment, trie_update) = storage_commitment_tree
        .commit()
        .context("Apply storage commitment tree updates")?;

    let root_idx = transaction
        .insert_storage_trie(&trie_update, block)
        .context("Persisting storage trie")?;

    transaction
        .insert_storage_root(block, root_idx)
        .context("Inserting storage root index")?;

    // Add new Sierra classes to class commitment tree.
    let mut class_commitment_tree = match block.parent() {
        Some(parent) => ClassCommitmentTree::load(transaction, parent)
            .context("Loading class commitment tree")?,
        None => ClassCommitmentTree::empty(transaction),
    }
    .with_verify_hashes(verify_hashes);

    for (sierra, casm) in state_update.declared_sierra_classes {
        let leaf_hash = pathfinder_common::calculate_class_commitment_leaf_hash(*casm);

        transaction
            .insert_class_commitment_leaf(block, &leaf_hash, casm)
            .context("Adding class commitment leaf")?;

        class_commitment_tree
            .set(*sierra, leaf_hash)
            .context("Update class commitment tree")?;
    }

    // Apply all class commitment tree changes.
    let (class_commitment, trie_update) = class_commitment_tree
        .commit()
        .context("Apply class commitment tree updates")?;

    let class_root_idx = transaction
        .insert_class_trie(&trie_update, block)
        .context("Persisting class trie")?;

    transaction
        .insert_class_root(block, class_root_idx)
        .context("Inserting class root index")?;

    Ok((storage_commitment, class_commitment))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt_bytes,
        BlockCommitmentSignature,
        BlockCommitmentSignatureElem,
        BlockHash,
        BlockHeader,
        BlockNumber,
        ClassHash,
        EventCommitment,
        ReceiptCommitment,
        SierraHash,
        StateCommitment,
        StateDiffCommitment,
        StateUpdate,
        TransactionCommitment,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_rpc::SyncState;
    use pathfinder_storage::StorageBuilder;
    use starknet_gateway_types::reply::{self, Block, GasPrices};

    use super::l2;
    use crate::state::sync::{consumer, ConsumerContext, SyncEvent};

    /// Generate some arbitrary block chain data from genesis onwards.
    ///
    /// Note: not very realistic data but is enough to drive tests.
    #[allow(clippy::type_complexity)]
    fn generate_block_data() -> Vec<(
        (
            Box<Block>,
            (TransactionCommitment, EventCommitment, ReceiptCommitment),
        ),
        Box<StateUpdate>,
        Box<BlockCommitmentSignature>,
        Box<StateDiffCommitment>,
        l2::Timings,
    )> {
        let genesis_header =
            BlockHeader::builder().finalize_with_hash(block_hash_bytes!(b"genesis block hash"));
        let mut headers = vec![genesis_header];
        for i in 1..3 {
            let block_hash =
                BlockHash(Felt::from_be_slice(format!("{i} block hash").as_bytes()).unwrap());
            let header = headers
                .last()
                .unwrap()
                .child_builder()
                .finalize_with_hash(block_hash);
            headers.push(header);
        }

        let mut data = Vec::new();
        let timings = l2::Timings::default();
        let mut parent_state_commitment = StateCommitment::ZERO;
        for header in headers {
            let state_update = Box::new(
                StateUpdate::default()
                    .with_block_hash(header.hash)
                    .with_parent_state_commitment(parent_state_commitment)
                    .with_state_commitment(header.state_commitment),
            );

            let block = Box::new(reply::Block {
                block_hash: header.hash,
                block_number: header.number,
                l1_gas_price: GasPrices {
                    price_in_wei: header.eth_l1_gas_price,
                    price_in_fri: header.strk_l1_gas_price,
                },
                l1_data_gas_price: GasPrices {
                    price_in_wei: header.eth_l1_data_gas_price,
                    price_in_fri: header.strk_l1_data_gas_price,
                },
                parent_block_hash: header.parent_hash,
                sequencer_address: Some(header.sequencer_address),
                state_commitment: header.state_commitment,
                status: reply::Status::AcceptedOnL2,
                timestamp: header.timestamp,
                transaction_receipts: vec![],
                transactions: vec![],
                starknet_version: header.starknet_version,
                l1_da_mode: Default::default(),
                transaction_commitment: header.transaction_commitment,
                event_commitment: header.event_commitment,
                receipt_commitment: Some(ReceiptCommitment(
                    Felt::from_hex_str(&format!("0x100{}", header.number)).unwrap(),
                )),
                state_diff_commitment: Some(StateDiffCommitment(
                    Felt::from_hex_str(&format!("0x200{}", header.number)).unwrap(),
                )),
                state_diff_length: Some(header.number.get()),
            });

            let signature = Box::new(BlockCommitmentSignature {
                r: BlockCommitmentSignatureElem(
                    Felt::from_hex_str(&format!("0x300{}", header.number)).unwrap(),
                ),
                s: BlockCommitmentSignatureElem(
                    Felt::from_hex_str(&format!("0x400{}", header.number)).unwrap(),
                ),
            });

            let state_diff_commitment = Box::new(block.state_diff_commitment.unwrap());

            data.push((
                (
                    block,
                    (
                        header.transaction_commitment,
                        header.event_commitment,
                        header.receipt_commitment,
                    ),
                ),
                state_update,
                signature,
                state_diff_commitment,
                timings,
            ));

            parent_state_commitment = header.state_commitment;
        }

        data
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn block_updates() {
        let storage = StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        let block_data = generate_block_data();
        let num_blocks = block_data.len();

        // Send block updates, followed by a reorg to genesis.
        for (a, b, c, d, e) in block_data {
            event_tx
                .send(SyncEvent::Block(a, b, c, d, e))
                .await
                .unwrap();
        }
        // Close the event channel which allows the consumer task to exit.
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();

        let tx = connection.transaction().unwrap();
        for i in 0..num_blocks {
            // TODO: Ideally we would test data consistency as well, but that will be easier
            // once we use the same types between storage, sync and gateway.
            let should_exist = tx
                .block_exists(BlockNumber::new_or_panic(i as u64).into())
                .unwrap();
            assert!(should_exist, "Block {i} should exist");
        }

        let should_not_exist = tx
            .block_exists(BlockNumber::new_or_panic(num_blocks as u64).into())
            .unwrap();
        assert!(!should_not_exist);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reorg() {
        let storage = StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        // Send block updates, followed by a reorg to genesis.
        for (a, b, c, d, e) in generate_block_data() {
            event_tx
                .send(SyncEvent::Block(a, b, c, d, e))
                .await
                .unwrap();
        }
        event_tx
            .send(SyncEvent::Reorg(BlockNumber::new_or_panic(2)))
            .await
            .unwrap();
        // Close the event channel which allows the consumer task to exit.
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();

        let tx = connection.transaction().unwrap();
        let genesis_exists = tx.block_exists(BlockNumber::GENESIS.into()).unwrap();
        assert!(genesis_exists);

        let block_1_exists = tx
            .block_exists(BlockNumber::new_or_panic(1).into())
            .unwrap();
        assert!(block_1_exists);

        let block_2_exists = tx
            .block_exists(BlockNumber::new_or_panic(2).into())
            .unwrap();
        assert!(!block_2_exists);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn blocks_are_not_skipped_after_a_reorg() {
        // A bug caused reorg'd block numbers to be skipped. This
        // was due to the expected block number not being updated
        // when handling the reorg.
        let storage = StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        // Send block updates, followed by a reorg removing block 2.
        // Then republish block 2, which should succeed.
        let blocks = generate_block_data();
        let block2 = blocks[2].clone();
        for (a, b, c, d, e) in blocks {
            event_tx
                .send(SyncEvent::Block(a, b, c, d, e))
                .await
                .unwrap();
        }
        event_tx
            .send(SyncEvent::Reorg(block2.0 .0.block_number))
            .await
            .unwrap();
        // This previously failed as the expected next block number was never
        // updated after a reorg, causing the reorg'd block numbers to be considered
        // duplicates and skipped - breaking sync.
        event_tx
            .send(SyncEvent::Block(
                block2.0, block2.1, block2.2, block2.3, block2.4,
            ))
            .await
            .unwrap();
        // Close the event channel which allows the consumer task to exit.
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();

        let tx = connection.transaction().unwrap();
        let genesis_exists = tx.block_exists(BlockNumber::GENESIS.into()).unwrap();
        assert!(genesis_exists);

        let block_1_exists = tx
            .block_exists(BlockNumber::new_or_panic(1).into())
            .unwrap();
        assert!(block_1_exists);
        // Block 2 should actually exist as well again.
        let block_2_exists = tx
            .block_exists(BlockNumber::new_or_panic(2).into())
            .unwrap();
        assert!(block_2_exists);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reorg_to_genesis() {
        let storage = StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        // Send block updates, followed by a reorg to genesis.
        for (a, b, c, d, e) in generate_block_data() {
            event_tx
                .send(SyncEvent::Block(a, b, c, d, e))
                .await
                .unwrap();
        }
        event_tx
            .send(SyncEvent::Reorg(BlockNumber::GENESIS))
            .await
            .unwrap();
        // Close the event channel which allows the consumer task to exit.
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();

        let tx = connection.transaction().unwrap();
        let genesis_exists = tx.block_exists(BlockNumber::GENESIS.into()).unwrap();
        assert!(!genesis_exists);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_cairo_contract() {
        let storage = StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(1);

        let class_hash = class_hash_bytes!(b"class hash");
        let expected_definition = b"cairo class definition".to_vec();

        event_tx
            .send(SyncEvent::CairoClass {
                definition: expected_definition.clone(),
                hash: class_hash,
            })
            .await
            .unwrap();
        // This closes the event channel which ends the consumer task.
        drop(event_tx);
        // UUT
        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();

        let tx = connection.transaction().unwrap();
        let definition = tx.class_definition(class_hash).unwrap().unwrap();

        assert_eq!(definition, expected_definition);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_sierra_contract() {
        let storage = StorageBuilder::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(1);

        let class_hash = felt_bytes!(b"class hash");
        let expected_definition = b"sierra class definition".to_vec();

        event_tx
            .send(SyncEvent::SierraClass {
                sierra_definition: expected_definition.clone(),
                sierra_hash: SierraHash(class_hash),
                casm_definition: b"casm definition".to_vec(),
                casm_hash: casm_hash_bytes!(b"casm hash"),
            })
            .await
            .unwrap();
        // This closes the event channel which ends the consumer task.
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();

        let tx = connection.transaction().unwrap();
        let definition = tx.class_definition(ClassHash(class_hash)).unwrap().unwrap();

        assert_eq!(definition, expected_definition);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_should_ignore_duplicate_blocks() {
        let storage = StorageBuilder::in_memory().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(5);

        let blocks = generate_block_data();
        let (a, b, c, d, e) = blocks[0].clone();

        event_tx
            .send(SyncEvent::Block(
                a.clone(),
                b.clone(),
                c.clone(),
                d.clone(),
                e,
            ))
            .await
            .unwrap();
        event_tx
            .send(SyncEvent::Block(a.clone(), b.clone(), c, d, e))
            .await
            .unwrap();
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
            websocket_txs: None,
            notifications: Default::default(),
        };

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        consumer(event_rx, context, tx).await.unwrap();
    }
}
