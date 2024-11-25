use std::sync::Arc;
#[cfg(feature = "aggregate_bloom")]
use std::sync::Mutex;

mod block;
mod class;
mod ethereum;
pub(crate) mod event;
mod reference;
mod reorg_counter;
mod signature;
mod state_update;
pub(crate) mod transaction;
mod trie;

pub use event::{
    EmittedEvent,
    EventFilter,
    EventFilterError,
    PageOfEvents,
    PAGE_SIZE_LIMIT as EVENT_PAGE_SIZE_LIMIT,
};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction as StarknetTransaction;
use pathfinder_common::{BlockNumber, TransactionHash};
pub(crate) use reorg_counter::ReorgCounter;
// Re-export this so users don't require rusqlite as a direct dep.
pub use rusqlite::TransactionBehavior;
pub use trie::{Node, NodeRef, RootIndexUpdate, StoredNode, TrieUpdate};

#[cfg(feature = "aggregate_bloom")]
use crate::bloom::AggregateBloom;

type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

pub struct Connection {
    connection: PooledConnection,
    bloom_filter_cache: Arc<crate::bloom::Cache>,
    #[cfg(feature = "aggregate_bloom")]
    running_aggregate: Arc<Mutex<AggregateBloom>>,
    trie_prune_mode: TriePruneMode,
}

impl Connection {
    pub(crate) fn new(
        connection: PooledConnection,
        bloom_filter_cache: Arc<crate::bloom::Cache>,
        #[cfg(feature = "aggregate_bloom")] running_aggregate: Arc<Mutex<AggregateBloom>>,
        trie_prune_mode: TriePruneMode,
    ) -> Self {
        Self {
            connection,
            bloom_filter_cache,
            #[cfg(feature = "aggregate_bloom")]
            running_aggregate,
            trie_prune_mode,
        }
    }

    pub fn transaction(&mut self) -> anyhow::Result<Transaction<'_>> {
        let tx = self.connection.transaction()?;
        Ok(Transaction {
            transaction: tx,
            bloom_filter_cache: self.bloom_filter_cache.clone(),
            #[cfg(feature = "aggregate_bloom")]
            running_aggregate: self.running_aggregate.clone(),
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
            bloom_filter_cache: self.bloom_filter_cache.clone(),
            #[cfg(feature = "aggregate_bloom")]
            running_aggregate: self.running_aggregate.clone(),
            trie_prune_mode: self.trie_prune_mode,
        })
    }
}

pub struct Transaction<'inner> {
    transaction: rusqlite::Transaction<'inner>,
    bloom_filter_cache: Arc<crate::bloom::Cache>,
    #[cfg(feature = "aggregate_bloom")]
    running_aggregate: Arc<Mutex<AggregateBloom>>,
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

impl<'inner> Transaction<'inner> {
    // The implementations here are intentionally kept as simple wrappers. This lets
    // the real implementations be kept in separate files with more reasonable
    // LOC counts and easier test oversight.

    fn inner(&self) -> &rusqlite::Transaction<'_> {
        &self.transaction
    }

    pub fn commit(self) -> anyhow::Result<()> {
        Ok(self.transaction.commit()?)
    }
}
