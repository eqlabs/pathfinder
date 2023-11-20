mod class;
pub mod l1;
pub mod l2;
mod pending;

use anyhow::Context;
use pathfinder_common::{
    BlockCommitmentSignature, BlockHash, BlockHeader, BlockNumber, CasmHash, Chain, ChainId,
    ClassCommitment, ClassHash, EventCommitment, GasPrice, SequencerAddress, SierraHash,
    StateCommitment, StateUpdate, StorageCommitment, TransactionCommitment,
};
use pathfinder_crypto::Felt;
use pathfinder_ethereum::{EthereumApi, EthereumStateUpdate};
use pathfinder_merkle_tree::contract_state::update_contract_state;
use pathfinder_merkle_tree::{ClassCommitmentTree, StorageCommitmentTree};
use pathfinder_rpc::PendingData;
use pathfinder_rpc::{
    v02::types::syncing::{self, NumberedBlock, Syncing},
    SyncState, TopicBroadcasters,
};
use pathfinder_storage::{Connection, Storage, Transaction, TransactionBehavior};
use primitive_types::H160;
use starknet_gateway_client::{GatewayApi, GossipApi};
use starknet_gateway_types::reply::Block;
use starknet_gateway_types::reply::PendingBlock;

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc::{self, Receiver};

use crate::state::l1::L1SyncContext;
use crate::state::l2::{BlockChain, L2SyncContext};

use tokio::sync::watch::Sender as WatchSender;

#[derive(Debug)]
pub enum SyncEvent {
    L1Update(EthereumStateUpdate),
    /// New L2 [block update](StateUpdate) found.
    Block(
        (Box<Block>, (TransactionCommitment, EventCommitment)),
        Box<StateUpdate>,
        Box<BlockCommitmentSignature>,
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
    Pending(Box<(PendingBlock, StateUpdate)>),
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
    pub pending_data: WatchSender<Arc<PendingData>>,
    pub pending_poll_interval: Option<Duration>,
    pub block_validation_mode: l2::BlockValidationMode,
    pub websocket_txs: Option<TopicBroadcasters>,
    pub block_cache_size: usize,
    pub restart_delay: Duration,
    pub verify_tree_hashes: bool,
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
            poll_interval: value.head_poll_interval,
        }
    }
}

impl<G, E> From<&SyncContext<G, E>> for L2SyncContext<G>
where
    G: Clone,
{
    fn from(value: &SyncContext<G, E>) -> Self {
        Self {
            broadcasters: value.websocket_txs.clone(),
            sequencer: value.sequencer.clone(),
            chain: value.chain,
            chain_id: value.chain_id,
            head_poll_interval: value.head_poll_interval,
            pending_poll_interval: value.pending_poll_interval,
            block_validation_mode: value.block_validation_mode,
            storage: value.storage.clone(),
        }
    }
}

/// Implements the main sync loop, where L1 and L2 sync results are combined.
#[allow(clippy::too_many_arguments)]
pub async fn sync<Ethereum, SequencerClient, F1, F2, L1Sync, L2Sync>(
    context: SyncContext<SequencerClient, Ethereum>,
    mut l1_sync: L1Sync,
    l2_sync: L2Sync,
) -> anyhow::Result<()>
where
    Ethereum: EthereumApi + Clone + Send + 'static,
    SequencerClient: GatewayApi + GossipApi + Clone + Send + Sync + 'static,
    F1: Future<Output = anyhow::Result<()>> + Send + 'static,
    F2: Future<Output = anyhow::Result<()>> + Send + 'static,
    L1Sync: FnMut(mpsc::Sender<SyncEvent>, L1SyncContext<Ethereum>) -> F1,
    L2Sync: FnOnce(
            mpsc::Sender<SyncEvent>,
            L2SyncContext<SequencerClient>,
            Option<(BlockNumber, BlockHash, StateCommitment)>,
            BlockChain,
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
        pending_data,
        pending_poll_interval: _,
        block_validation_mode: _,
        websocket_txs: _,
        block_cache_size,
        restart_delay,
        verify_tree_hashes: _,
    } = context;

    let mut db_conn = storage
        .connection()
        .context("Creating database connection")?;

    // TODO: consider increasing the capacity.
    let (event_sender, event_receiver) = mpsc::channel(2);

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
        head_poll_interval,
    ));

    // Start L1 producer task. Clone the event sender so that the channel remains open
    // even if the producer task fails.
    let mut l1_handle = tokio::spawn(l1_sync(event_sender.clone(), l1_context.clone()));

    let latest_blocks = latest_n_blocks(&mut db_conn, block_cache_size)
        .await
        .context("Fetching latest blocks from storage")?;
    let block_chain = BlockChain::with_capacity(1_000, latest_blocks);

    // Start L2 producer task. Clone the event sender so that the channel remains open
    // even if the producer task fails.
    let mut l2_handle = tokio::spawn(l2_sync(
        event_sender.clone(),
        l2_context.clone(),
        l2_head,
        block_chain,
    ));

    let consumer_context = ConsumerContext {
        storage,
        state,
        pending_data,
        verify_tree_hashes: context.verify_tree_hashes,
    };
    let mut consumer_handle = tokio::spawn(consumer(event_receiver, consumer_context));

    /// Delay before restarting L1 or L2 tasks if they fail. This delay helps prevent DoS if these
    /// tasks are crashing.
    #[cfg(not(test))]
    const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::from_secs(60);
    #[cfg(test)]
    const RESET_DELAY_ON_FAILURE: std::time::Duration = std::time::Duration::ZERO;

    loop {
        tokio::select! {
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
                let fut = l2_sync(event_sender.clone(), l2_context.clone(), l2_head, block_chain);

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

                anyhow::bail!("Sync process terminated");
            }
        }
    }
}

struct ConsumerContext {
    pub storage: Storage,
    pub state: Arc<SyncState>,
    pub pending_data: WatchSender<Arc<PendingData>>,
    pub verify_tree_hashes: bool,
}

async fn consumer(mut events: Receiver<SyncEvent>, context: ConsumerContext) -> anyhow::Result<()> {
    let ConsumerContext {
        storage,
        state,
        pending_data,
        verify_tree_hashes,
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
                l1_update(&mut db_conn, &update).await?;
                tracing::info!("L1 sync updated to block {}", update.block_number);
            }
            Block((block, (tx_comm, ev_comm)), state_update, signature, timings) => {
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
                    ev_comm,
                    *state_update,
                    *signature,
                    verify_tree_hashes,
                    storage.clone(),
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

                let now_timestamp = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
                let latency = now_timestamp.saturating_sub(block_timestamp.get());

                let download_time = (timings.block_download
                    + timings.class_declaration
                    + timings.state_diff_download
                    + timings.signature_download)
                    .as_secs_f64();

                metrics::gauge!("block_download", download_time);
                metrics::gauge!("block_processing", update_t.as_secs_f64());
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
                        tracing::debug!("Updated Starknet state with block {} after {:2}s ({:2}s avg). contracts ({:2}s), {} storage updates ({:2}s). Block downloaded in {:2}s, state diff in {:2}s, signature in {:2}s",
                                    block_number,
                                    block_time.as_secs_f32(),
                                    block_time_avg.as_secs_f32(),
                                    timings.class_declaration.as_secs_f32(),
                                    storage_updates,
                                    update_t.as_secs_f32(),
                                    timings.block_download.as_secs_f32(),
                                    timings.state_diff_download.as_secs_f32(),
                                    timings.signature_download.as_secs_f32(),
                                );
                    }
                }
            }
            Reorg(reorg_tail) => {
                l2_reorg(&mut db_conn, reorg_tail)
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
                tokio::task::block_in_place(|| {
                    let tx = db_conn
                        .transaction()
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
                tokio::task::block_in_place(|| {
                    let tx = db_conn
                        .transaction()
                        .context("Creating database transaction")?;
                    tx.insert_sierra_class(
                        &sierra_hash,
                        &sierra_definition,
                        &casm_hash,
                        &casm_definition,
                        pathfinder_compiler::COMPILER_VERSION,
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
                    pending_data.send_replace(Arc::new(data));
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

        // We need to reverse the order here because we want the last `N` blocks in chronological order.
        // Our sql query gives us the last `N` blocks but in reverse order (ORDER BY DESC), so we undo that here.
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
    sequencer: impl GatewayApi + GossipApi,
    starting_block_hash: BlockHash,
    starting_block_num: BlockNumber,
    poll_interval: Duration,
) -> anyhow::Result<()> {
    let starting = NumberedBlock::from((starting_block_hash, starting_block_num));
    let mut last_propagated = Instant::now();

    loop {
        match sequencer.head().await {
            Ok((block_number, block_hash)) => {
                let latest = NumberedBlock::from((block_hash, block_number));

                match &mut *state.status.write().await {
                    sync_status @ Syncing::False(_) => {
                        *sync_status = Syncing::Status(syncing::Status {
                            starting,
                            current: starting,
                            highest: latest,
                        });

                        metrics::gauge!("current_block", starting.number.get() as f64);
                        metrics::gauge!("highest_block", latest.number.get() as f64);

                        propagate_head(&sequencer, &mut last_propagated, latest).await;

                        tracing::debug!(
                            status=%sync_status,
                            "Updated sync status",
                        );
                    }
                    Syncing::Status(status) => {
                        if status.highest.hash != latest.hash {
                            status.highest = latest;

                            metrics::gauge!("highest_block", latest.number.get() as f64);

                            propagate_head(&sequencer, &mut last_propagated, latest).await;

                            tracing::debug!(
                                %status,
                                "Updated sync status",
                            );
                        }
                    }
                }

                // duplicate_cache_time for gossipsub defaults to 1 minute
                if last_propagated.elapsed() > Duration::from_secs(120) {
                    propagate_head(&sequencer, &mut last_propagated, latest).await;
                }
            }
            Err(e) => {
                tracing::error!(error=%e, "Failed to fetch latest block");
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

async fn propagate_head(
    gossiper: &impl GossipApi,
    last_propagated: &mut Instant,
    head: NumberedBlock,
) {
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
#[allow(clippy::too_many_arguments)]
async fn l2_update(
    connection: &mut Connection,
    block: Block,
    transaction_commitment: TransactionCommitment,
    event_commitment: EventCommitment,
    state_update: StateUpdate,
    signature: BlockCommitmentSignature,
    verify_tree_hashes: bool,
    // we need this so that we can create extra read-only transactions for
    // parallel contract state updates
    storage: Storage,
) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;
        let (storage_commitment, class_commitment) = update_starknet_state(
            &transaction,
            &state_update,
            verify_tree_hashes,
            block.block_number,
            storage,
        )
        .context("Updating Starknet state")?;
        let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);

        // Ensure that roots match.. what should we do if it doesn't? For now the whole sync process ends..
        #[cfg(not(feature = "p2p"))]
        anyhow::ensure!(
            state_commitment == block.state_commitment,
            "State root mismatch"
        );

        // FIXME EEEEEEE does not work for non-proxy nodeeeeeees
        // In p2p the state commitment can be missing, which is marked as 0.
        // Once signature support is added this way of verifying state commitment will be deprecated.
        #[cfg(feature = "p2p")]
        anyhow::ensure!(
            block.state_commitment == StateCommitment::ZERO
                || state_commitment == block.state_commitment,
            "State root mismatch"
        );

        let transaction_count = block.transactions.len();
        let event_count = block
            .transaction_receipts
            .iter()
            .map(|r| r.events.len())
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
            transaction_count,
            event_count,
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

        transaction.commit().context("Commit database transaction")
    })?;

    Ok(())
}

async fn l2_reorg(connection: &mut Connection, reorg_tail: BlockNumber) -> anyhow::Result<()> {
    tokio::task::block_in_place(move || {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("Create database transaction")?;

        let mut head = transaction
            .block_id(pathfinder_storage::BlockId::Latest)
            .context("Querying latest block number")?
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
                            *contract_address,
                            &update.storage,
                            update.nonce,
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

    for (contract, update) in &state_update.system_contract_updates {
        let update_result = update_contract_state(
            *contract,
            &update.storage,
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
    let (storage_commitment, nodes) = storage_commitment_tree
        .commit()
        .context("Apply storage commitment tree updates")?;

    let root_idx = if !storage_commitment.0.is_zero() {
        let root_idx = transaction
            .insert_storage_trie(storage_commitment, &nodes)
            .context("Persisting storage trie")?;

        Some(root_idx)
    } else {
        None
    };

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

    for (sierra, casm) in &state_update.declared_sierra_classes {
        let leaf_hash = pathfinder_common::calculate_class_commitment_leaf_hash(*casm);

        transaction
            .insert_class_commitment_leaf(block, &leaf_hash, casm)
            .context("Adding class commitment leaf")?;

        class_commitment_tree
            .set(*sierra, leaf_hash)
            .context("Update class commitment tree")?;
    }

    // Apply all class commitment tree changes.
    let (class_commitment, nodes) = class_commitment_tree
        .commit()
        .context("Apply class commitment tree updates")?;

    let class_root_idx = if !class_commitment.0.is_zero() {
        let class_root_idx = transaction
            .insert_class_trie(class_commitment, &nodes)
            .context("Persisting class trie")?;

        Some(class_root_idx)
    } else {
        None
    };

    transaction
        .insert_class_root(block, class_root_idx)
        .context("Inserting class root index")?;

    Ok((storage_commitment, class_commitment))
}

#[cfg(test)]
mod tests {
    use super::l2;
    use crate::state::sync::{consumer, ConsumerContext, SyncEvent};
    use pathfinder_common::{
        felt_bytes, BlockHash, BlockHeader, BlockNumber, ClassHash, EventCommitment, SierraHash,
        StateCommitment, StateUpdate, TransactionCommitment,
    };
    use pathfinder_common::{macro_prelude::*, BlockCommitmentSignature};
    use pathfinder_crypto::Felt;
    use pathfinder_rpc::SyncState;
    use pathfinder_storage::Storage;
    use starknet_gateway_types::reply;
    use starknet_gateway_types::reply::Block;
    use std::sync::Arc;

    /// Generate some arbitrary block chain data from genesis onwards.
    ///
    /// Note: not very realistic data but is enough to drive tests.
    #[allow(clippy::type_complexity)]
    fn generate_block_data() -> Vec<(
        (Box<Block>, (TransactionCommitment, EventCommitment)),
        Box<StateUpdate>,
        Box<BlockCommitmentSignature>,
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
                gas_price: Some(header.gas_price),
                parent_block_hash: header.parent_hash,
                sequencer_address: Some(header.sequencer_address),
                state_commitment: header.state_commitment,
                status: reply::Status::AcceptedOnL2,
                timestamp: header.timestamp,
                transaction_receipts: vec![],
                transactions: vec![],
                starknet_version: header.starknet_version,
            });

            let signature = Box::new(BlockCommitmentSignature {
                r: block_commitment_signature_elem!("0x1001"),
                s: block_commitment_signature_elem!("0x1002"),
            });

            data.push((
                (
                    block,
                    (header.transaction_commitment, header.event_commitment),
                ),
                state_update,
                signature,
                timings,
            ));

            parent_state_commitment = header.state_commitment;
        }

        data
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn block_updates() {
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        let block_data = generate_block_data();
        let num_blocks = block_data.len();

        // Send block updates, followed by a reorg to genesis.
        for (a, b, c, d) in block_data {
            event_tx.send(SyncEvent::Block(a, b, c, d)).await.unwrap();
        }
        // Close the event channel which allows the consumer task to exit.
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
        };

        consumer(event_rx, context).await.unwrap();

        let tx = connection.transaction().unwrap();
        for i in 0..num_blocks {
            // TODO: Ideally we would test data consistency as well, but that will be easier once we use
            // the same types between storage, sync and gateway.
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
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        // Send block updates, followed by a reorg to genesis.
        for (a, b, c, d) in generate_block_data() {
            event_tx.send(SyncEvent::Block(a, b, c, d)).await.unwrap();
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
        };

        consumer(event_rx, context).await.unwrap();

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
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        // Send block updates, followed by a reorg removing block 2.
        // Then republish block 2, which should succeed.
        let blocks = generate_block_data();
        let block2 = blocks[2].clone();
        for (a, b, c, d) in blocks {
            event_tx.send(SyncEvent::Block(a, b, c, d)).await.unwrap();
        }
        event_tx
            .send(SyncEvent::Reorg(block2.0 .0.block_number))
            .await
            .unwrap();
        // This previously failed as the expected next block number was never
        // updated after a reorg, causing the reorg'd block numbers to be considered
        // duplicates and skipped - breaking sync.
        event_tx
            .send(SyncEvent::Block(block2.0, block2.1, block2.2, block2.3))
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
        };

        consumer(event_rx, context).await.unwrap();

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
        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(100);

        // Send block updates, followed by a reorg to genesis.
        for (a, b, c, d) in generate_block_data() {
            event_tx.send(SyncEvent::Block(a, b, c, d)).await.unwrap();
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
        };

        consumer(event_rx, context).await.unwrap();

        let tx = connection.transaction().unwrap();
        let genesis_exists = tx.block_exists(BlockNumber::GENESIS.into()).unwrap();
        assert!(!genesis_exists);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_cairo_contract() {
        let storage = Storage::in_memory().unwrap();
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
        };

        consumer(event_rx, context).await.unwrap();

        let tx = connection.transaction().unwrap();
        let definition = tx.class_definition(class_hash).unwrap().unwrap();

        assert_eq!(definition, expected_definition);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn new_sierra_contract() {
        let storage = Storage::in_memory().unwrap();
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
        };

        consumer(event_rx, context).await.unwrap();

        let tx = connection.transaction().unwrap();
        let definition = tx.class_definition(ClassHash(class_hash)).unwrap().unwrap();

        assert_eq!(definition, expected_definition);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn consumer_should_ignore_duplicate_blocks() {
        let storage = Storage::in_memory().unwrap();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(5);

        let blocks = generate_block_data();
        let (a, b, c, d) = blocks[0].clone();

        event_tx
            .send(SyncEvent::Block(a.clone(), b.clone(), c.clone(), d))
            .await
            .unwrap();
        event_tx
            .send(SyncEvent::Block(a.clone(), b.clone(), c, d))
            .await
            .unwrap();
        drop(event_tx);

        let (tx, _rx) = tokio::sync::watch::channel(Default::default());
        let context = ConsumerContext {
            storage,
            state: Arc::new(SyncState::default()),
            pending_data: tx,
            verify_tree_hashes: false,
        };

        consumer(event_rx, context).await.unwrap();
    }
}
