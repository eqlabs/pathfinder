use std::sync::{Arc, Mutex};

mod block;
mod class;
mod ethereum;
pub mod event;
mod reference;
mod signature;
mod state_update;
pub(crate) mod transaction;
mod trie;

use event::RunningEventFilter;
pub use event::{
    EmittedEvent,
    EventConstraints,
    EventFilterError,
    PageOfEvents,
    PAGE_SIZE_LIMIT as EVENT_PAGE_SIZE_LIMIT,
};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction as StarknetTransaction;
use pathfinder_common::{BlockNumber, TransactionHash};
// Re-export this so users don't require rusqlite as a direct dep.
pub use rusqlite::TransactionBehavior;
pub use trie::{Node, NodeRef, RootIndexUpdate, StoredNode, TrieStorageIndex, TrieUpdate};

use crate::bloom::AggregateBloomCache;

type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

pub struct Connection {
    connection: PooledConnection,
    event_filter_cache: Arc<AggregateBloomCache>,
    running_event_filter: Arc<Mutex<RunningEventFilter>>,
    trie_prune_mode: TriePruneMode,
}

impl Connection {
    pub(crate) fn new(
        connection: PooledConnection,
        event_filter_cache: Arc<AggregateBloomCache>,
        running_event_filter: Arc<Mutex<RunningEventFilter>>,
        trie_prune_mode: TriePruneMode,
    ) -> Self {
        Self {
            connection,
            event_filter_cache,
            running_event_filter,
            trie_prune_mode,
        }
    }

    pub fn transaction(&mut self) -> anyhow::Result<Transaction<'_>> {
        let tx = self.connection.transaction()?;
        Ok(Transaction {
            transaction: tx,
            event_filter_cache: self.event_filter_cache.clone(),
            running_event_filter: self.running_event_filter.clone(),
            trie_prune_mode: self.trie_prune_mode,
        })
    }

    pub fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> anyhow::Result<Transaction<'_>> {
        let tx = self.connection.transaction_with_behavior(behavior)?;
        Ok(Transaction {
            transaction: tx,
            event_filter_cache: self.event_filter_cache.clone(),
            running_event_filter: self.running_event_filter.clone(),
            trie_prune_mode: self.trie_prune_mode,
        })
    }
}

pub struct Transaction<'inner> {
    transaction: rusqlite::Transaction<'inner>,
    event_filter_cache: Arc<AggregateBloomCache>,
    running_event_filter: Arc<Mutex<RunningEventFilter>>,
    trie_prune_mode: TriePruneMode,
}

#[derive(Debug, Clone, Copy)]
pub enum TriePruneMode {
    /// Keep all merkle trie history.
    Archive,
    /// Prune merkle trie history. Only keep the last few blocks, as well as the
    /// latest block.
    Prune { num_blocks_kept: u64 },
}

type TransactionWithReceipt = (StarknetTransaction, Receipt, Vec<Event>, BlockNumber);

type TransactionDataForBlock = (StarknetTransaction, Receipt, Vec<Event>);

type EventsForBlock = (TransactionHash, Vec<Event>);

impl Transaction<'_> {
    // The implementations here are intentionally kept as simple wrappers. This lets
    // the real implementations be kept in separate files with more reasonable
    // LOC counts and easier test oversight.

    fn inner(&self) -> &rusqlite::Transaction<'_> {
        &self.transaction
    }

    pub fn commit(self) -> anyhow::Result<()> {
        Ok(self.transaction.commit()?)
    }

    pub fn trie_pruning_enabled(&self) -> bool {
        matches!(self.trie_prune_mode, TriePruneMode::Prune { .. })
    }

    /// Store the in-memory [`Storage`](crate::Storage) state in the database.
    /// To be performed on shutdown.
    pub fn store_in_memory_state(self) -> anyhow::Result<()> {
        self.store_running_event_filter()?.commit()
    }

    /// Resets the in-memory [`Storage`](crate::Storage) state. Required after
    /// each reorg.
    pub fn reset_in_memory_state(&self, head: BlockNumber) -> anyhow::Result<()> {
        self.event_filter_cache.reset();
        self.rebuild_running_event_filter(head)
    }
}
