//! Controls the tracking of the tip of the starknet chain.
//!
//! ## Top level components:
//!
//!     1. Central consumer loop which performs all the database IO (reads and writes), it drives an
//!     2. L1 producer task and an
//!     3. L2 producer task
//!
//! Both L1 and L2 tasks are decoupled entirely from storage which is great as it makes reasoning about
//! state much easier.
//!
//! The L2 producer communicates to the consumer loop via
//!
//! ## L2 producer
//!
//! The L2 producer is split into three modes:
//!     1. Tracking
//!         Follows the tip of the chain until it no longer attaches to our local chain. This can be due to
//!         a reorg, or missing block data locally.
//!     2. Repair
//!         Fetches missing block data
//!     3. Reorg
//!         Finds the last point at which the local data matches the chain
//!
//! The consumer consumes events from the producer via a channel. The channel closes once the producer ends, which
//! indicates to the consumer that it should check the producers task handle for further information on how to proceed.
//! This is used to drive the state machine of the L2 process.
//!
//! L2::tracking -> reorg? -> L2::reorg  -> L2::tracking
//!              -> gap?   -> L2::repair -> L2::tracking
//!
//! ## L1 producer
//!
//! Since L1 == L2 depends on the L2 process as well, we cannot spawn the L1 and L2 processes without a sync point. To simplify
//! this sync point, we let L2 spawn as a task but keep the L1 stuff as a basic future. This means its not a consumer + producer
//! schema (can't have both L1 and L2 do this). Instead L1 is just two simple functions:
//!     1. Track the latest L1 starknet state
//!     2. Return the previous L1 state
//!
//! The "state machine" for this looks as follows:
//!
//!                       (a)
//! L1::tracking -> return [L1State] -> L1 == L2? -> yes -> update L1 == L2 -> L1::tracking
//!                                               -> no  -> L1::previous    -> repeat from (a)

use anyhow::Context;
use futures::FutureExt;

use tokio::sync::mpsc::Sender as MspcSender;
use tokio::sync::watch::Receiver as WatchReceiver;
use tokio::task::JoinHandle;

use pathfinder_common::{BlockHash, BlockNumber};
use pathfinder_merkle_tree::tree::Update as TrieUpdate;
use pathfinder_storage::Storage;

use crate::sync::{BlockBody, BlockHeader};

/// Uniquely identifies a Starknet block via its number and hash.
#[derive(Copy, Clone, Debug)]
struct BlockId {
    pub number: BlockNumber,
    pub hash: BlockHash,
}

/// A wrapper around [Storage] which also contains the latest local state
/// of starknet for ease of access.
struct State {
    head: BlockId,
    storage: Storage,
    // TODO: pending block data
}

impl State {
    // A lot of this is probably re-useable (and required) for sync mode as well.
    // Will see how this factors out once we get there.
    async fn new(mut storage: Storage) -> anyhow::Result<Self> {
        let head = tokio::task::block_in_place(|| {
            let mut connection = storage
                .connection()
                .context("Creating database connection")?;
            let mut tx = connection
                .transaction()
                .context("Creating database transaction")?;

            let head = todo!("Fetch L2 head from storage");

            anyhow::Ok(head)
        })
        .context("Initializing state from database")?;

        Ok(Self { head, storage })
    }

    async fn update_l1_head(&self) -> Result<(), L1UpdateError> {
        // TODO: all the sql stuff.
        let storage = self.storage.clone();
        let jh = tokio::task::spawn_blocking(move || {
            let mut connection = storage
                .connection()
                .context("Creating database connection")?;
            let tx = connection
                .transaction()
                .context("Creating database transaction")?;

            let exists: bool = tx
                .query_row("EXISTS(canonical block)", [], |row| todo!())
                .context("Querying database for existence of block")?;

            if exists {
                tx.execute("update L1 == L2 pointer", [])
                    .context("Updating L1 == L2 pointer")?;
                tx.commit().context("Committing database transaction")?;
                Ok(())
            } else {
                Err(L1UpdateError::Invalid)
            }
        });

        jh.await.context("Joining database task")?
    }

    async fn insert_cairo0_class(&self, class: ()) -> anyhow::Result<()> {
        todo!();
    }

    async fn insert_cairo1_class(&self, class: ()) -> anyhow::Result<()> {
        todo!();
    }

    async fn push_block(&self, block: L2Update) -> anyhow::Result<()> {
        todo!("Insert all the block things into the database");
    }

    async fn reorg(&self, head: BlockId) -> anyhow::Result<()> {
        todo!("Delete all blocks > head");
    }

    async fn block_ids(
        &self,
        range: impl std::ops::RangeBounds<BlockNumber>,
    ) -> anyhow::Result<Vec<BlockId>> {
        todo!("Return all block hashes and numbers in the given range");
    }
}

/// Tracks the tip of the Starknet chain and its status on L1.
async fn track(
    storage: Storage,
    headers: WatchReceiver<BlockHeader>,
    l2_source: impl super::Source + 'static + Clone,
    mut state: State,
) -> anyhow::Result<()> {
    let l1_head = BlockId {
        number: BlockNumber::GENESIS,
        hash: BlockHash::ZERO,
    };
    // TODO: consider whether this should be a spawned task instead, to allow for parallel execution.
    let mut l1_source = poll_latest_l1_status((), l1_head).boxed();

    let (l2_sender, mut l2_events) = tokio::sync::mpsc::channel(1);

    let mut l2_task = L2Task::spawn_track(state.head, headers.clone(), l2_sender.clone());

    // Loop until we somehow lose track of the chain, and should instead switch to
    // sync mode -- is this even something that realistically happens in other clients?
    // Or should sync be a once off only..
    loop {
        // TODO: factor out for testing.
        tokio::select! {
            l1_update = &mut l1_source => {
                let l1_update = l1_update.context("Fetching next L1 update")?;
                l1_source = match update_l1_state(storage.clone(), l1_update.clone()).await {
                    Ok(_) => {
                        tracing::info!(number=%l1_update.starknet.number, hash=%l1_update.starknet.hash, "Updated L1 state");
                        // state.l1_head = l1_update;
                        poll_latest_l1_status((), l1_update.starknet.clone()).boxed()
                    },
                    Err(L1UpdateError::Invalid) => {
                        tracing::debug!(L1=?l1_update, "L1 update did not match local L2 state, trying further back in history");
                        parent_l1_status((), l1_update).boxed()
                    },
                    Err(reason) => {
                        tracing::error!(%reason, "Failed to update L1 state");
                        poll_latest_l1_status((), l1_update.starknet.clone()).boxed()
                    }
                }
            },
            l2_event = l2_events.recv() => {
                // Factor out for testing. And probably each branch contents as well..
                match l2_event {
                    Some(event) => handle_l2_event(storage.clone(), event, &state).await.context("Handling L2 event")?,
                    None => {
                        match l2_task {
                            L2Task::Track(jh) => {
                                match jh.await.context("Joining chain tracking task")? {
                                    Ok(chain_tip) if chain_tip.number <= state.head.number + 1 => {
                                        // TODO: add reorg info to trace
                                        tracing::info!("Reorg detected, initiating repair");
                                        let local_blocks = state.block_ids(chain_tip.number - 100..=chain_tip.number).await.context("Fetching block hashes")?;
                                        l2_task = L2Task::spawn_reorg(local_blocks, l2_source.clone());
                                    }
                                    Ok(chain_tip) => {
                                        // TODO: consider exiting to switch back to sync mode if the gap is too large?
                                        tracing::info!("Gap in chain detected, intiating repair");
                                        l2_task = L2Task::spawn_repair(state.head, chain_tip, l2_source.clone(), l2_sender.clone());
                                    }
                                    // Probably exit the entire process, and let the outside monitor reset things
                                    Err(e) => todo!("Figure out what a good reaction here is.."),
                                }
                            }
                            L2Task::Repair(jh) => match jh.await.context("Joining chain repair task")? {
                                Ok(result) => {
                                    tracing::debug!("Chain repair completed");
                                    l2_task = L2Task::spawn_track(state.head, headers.clone(), l2_sender.clone());
                                }
                                // Probably exit the entire process, and let the outside monitor reset things
                                Err(e) => todo!("Figure out what a good reaction here is.."),
                            },
                            // TODO: fix -- this task should also take in the Sender<Event> otherwise the [None] above will immedietely trigger..
                            L2Task::Reorg(jh) => match jh.await.context("Joining reorg task")? {
                                Ok(new_head) => {
                                    state.reorg(new_head).await.context("Reorg'ing blocks from storage")?;
                                    tracing::info!("Reorg repair completed");
                                    l2_task = L2Task::spawn_track(state.head, headers.clone(), l2_sender.clone());
                                },
                                Err(ReorgError::NoMatch(previous)) => {
                                    tracing::warn!("Reorg exceeded search chunk, searching further");
                                    let local_blocks = state.block_ids(previous.number - 100..previous.number).await.context("Fetching block hashes")?;
                                    l2_task = L2Task::spawn_reorg(local_blocks, l2_source.clone());
                                },
                                // Probably exit the entire process, and let the outside monitor reset things
                                Err(ReorgError::Other(e)) => todo!("Figure it out"),
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum L1UpdateError {
    #[error("L1 update is invalid")]
    Invalid,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

async fn update_l1_state(storage: Storage, update: L1State) -> Result<(), L1UpdateError> {
    todo!();
}

async fn handle_l2_event(storage: Storage, event: L2Event, state: &State) -> anyhow::Result<()> {
    match event {
        L2Event::Cairo1Class(_) => {
            tracing::debug!("Inserted sierra class into storage");
            todo!("Insert into storage");
        }
        L2Event::Cairo0Class(_) => {
            tracing::debug!("Inserted cairo class into storage");
            todo!("Insert into storage");
        }
        L2Event::Block(b) => {
            // Assumption: all required classes have already been inserted prior to this.
            tracing::info!(hash=%b.header.hash, "Updated Starknet state");
            todo!("Insert block data into storage");
        }
    }
}

/// Poll's Starknet's L1 contract until the L1 [BlockId] changes from the current one,
/// and returns the new L1 [L1State].
async fn poll_latest_l1_status(eth_client: (), current: BlockId) -> anyhow::Result<L1State> {
    todo!("Ethereum client should implement this");
}

/// Returns the Starknet [L1State] which is the parent block of the input state.
async fn parent_l1_status(eth_client: (), state: L1State) -> anyhow::Result<L1State> {
    todo!("Ethereum client should implement this");
}

#[derive(Clone, Debug)]
struct L1State {
    starknet: BlockId,
    ethereum: EthBlockId,
}

#[derive(Clone, Debug)]
struct EthBlockId {
    // TODO: change these to actual ethereum types
    number: u64,
    hash: [u8; 32],
}

struct L2Update {
    header: BlockHeader,
    body: BlockBody,
    storage_trie: TrieUpdate,
    contract_tries: Vec<TrieUpdate>,
    class_trie: TrieUpdate,
}

/// The event emitted by the L2 tracking process.
///
/// Note that class definitions are emitted as individual events and are not part of the block update.
///
/// The benefits are:
///     1. Smaller memory footprint. A block can in theory have as many new class declarations as transactions
///        in the block. While this is unlikely, the point is that a block can potentially contain many declarations.
///        A class declaration can also be quite large. Handling them 1-by-1 means that we have a bounded memory
///        footprint for class declarations.
///
///     2. Simplifies handling of pending block class declarations as the pending task can just emit class declarations
///        as normal, and they will be present for usage in pending related rpc calls.
///
/// The downsides:
///     1. L2 process must self-enforce that all new class declarations are emitted as events prior to emitting the block.
///        Maybe we can find some type-pattern that will make this more obvious that it has occurred?
///
///     2. It becomes difficult / impossible to delete classes that were reorg'd away or got reverted. Probably a minor issue
///        since it is likely that a reverted class declaration will get re-declared shortly thereafter again.
enum L2Event {
    // TODO: fill in details here
    Cairo1Class(()),
    // TODO: fill in details here
    Cairo0Class(()),
    Block(L2Update),
}

/// Tracks the tip of the starknet chain and emits new L2 data events.
///
/// Tracking ends once the external chain's tip no longer connects to our local chain. This can occur
/// for one of two reasons:
///     1. There was a reorg, or
///     2. there is a gap between our local state and the external chain.
///
/// This function returns the block which is not connected to the tip of our chain.
async fn track_starknet(
    mut head: BlockId,
    mut headers: WatchReceiver<BlockHeader>,
    events: MspcSender<L2Event>,
) -> anyhow::Result<BlockId> {
    let mut next = headers.borrow_and_update().clone();
    if next.hash == head.hash {
        headers.changed().await.context("Waiting for new header")?;
        next = headers.borrow().clone();
    }

    while next.parent == head.hash {
        headers.changed().await.context("Waiting for new header")?;
        next = headers.borrow().clone();

        // TODO: fetch block body, state update
        // TODO: process block body, state update
        // TODO: fetch declared classes
        // TODO: process classes
        // TODO: emit classes
        // TODO: emit block
        // TODO: figure out pending block.. can probably just be part of header source somehow instead?

        head.number = next.number;
        head.hash = next.hash;
    }

    Ok(BlockId {
        number: next.number,
        hash: next.hash,
    })
}

struct RepairResult {
    /// The starting block of the repair
    start: BlockId,
    /// The target block to reach
    target: BlockId,
    /// The actual block reached
    new_head: BlockId,
}

/// Downloads and emits the missing block data as [events](L2Event). Does a best effort
/// attempt i.e. will stop at the first missing block.
async fn repair_gap(
    head: BlockId,
    target: BlockId,
    source: impl super::Source,
    events: MspcSender<L2Event>,
) -> anyhow::Result<RepairResult> {
    let block_range = head.number + 1..=target.number;

    let headers = source
        .block_headers(block_range.clone())
        .await
        .context("Fetching block headers")?;

    let bodies = source
        .block_bodies(block_range.clone())
        .await
        .context("Fetching block bodies")?;

    let state_updates = source
        .state_updates(block_range)
        .await
        .context("Fetching state updates")?;

    // TODO: process block headers chain
    // TODO: process state updates
    // TODO: process missing classes
    // TODO: emit missing classes
    // TODO: emit blocks

    Ok(RepairResult {
        start: head,
        target,
        new_head: target, // TODO: fill in the actual stopping point.
    })
}

enum L2Task {
    Track(JoinHandle<anyhow::Result<BlockId>>),
    Repair(JoinHandle<anyhow::Result<RepairResult>>),
    Reorg(JoinHandle<Result<BlockId, ReorgError>>),
}

impl L2Task {
    fn spawn_track(
        head: BlockId,
        headers: tokio::sync::watch::Receiver<BlockHeader>,
        events: MspcSender<L2Event>,
    ) -> Self {
        let jh = tokio::spawn(track_starknet(head, headers, events));

        Self::Track(jh)
    }

    fn spawn_repair(
        head: BlockId,
        target: BlockId,
        source: impl super::Source + 'static, // TODO: 'static?
        events: MspcSender<L2Event>,
    ) -> Self {
        let jh = tokio::spawn(async move { repair_gap(head, target, source, events).await });

        Self::Repair(jh)
    }

    fn spawn_reorg(
        local: Vec<BlockId>,
        source: impl super::Source + 'static, // TODO: 'static?
    ) -> Self {
        let jh = tokio::spawn(async move { determine_reorg_extent(local, source).await });

        Self::Reorg(jh)
    }
}

#[derive(thiserror::Error, Debug)]
enum ReorgError {
    #[error("No match found")]
    NoMatch(BlockId),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Finds the extent of a reorg by finding the latest point at which our local data
/// matches the public chain.
async fn determine_reorg_extent(
    local: Vec<BlockId>,
    source: impl super::Source,
) -> Result<BlockId, ReorgError> {
    let start = local.first().context("Local chain is empty")?.number;
    let stop = local.last().context("Local chain is empty")?.number;

    // This may be a poor fit for the gateway api.. cross that bridge later.
    let headers = source
        .block_headers(start..=stop)
        .await
        .context("Fetching block headers")?;

    let new_head = headers
        .iter()
        .zip(local.iter())
        .take_while(|(a, b)| a.hash == b.hash)
        .last()
        .ok_or(ReorgError::NoMatch(local[0]))?
        .1;

    Ok(*new_head)
}
