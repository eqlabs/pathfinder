use std::sync::Arc;

mod block;
mod class;
mod ethereum;
mod event;
mod reference;
mod reorg_counter;
mod signature;
mod state_update;
pub(crate) mod transaction;
mod trie;

use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
// Re-export this so users don't require rusqlite as a direct dep.
pub use rusqlite::TransactionBehavior;

pub use event::KEY_FILTER_LIMIT as EVENT_KEY_FILTER_LIMIT;
pub use event::PAGE_SIZE_LIMIT as EVENT_PAGE_SIZE_LIMIT;
pub use event::{EmittedEvent, EventFilter, EventFilterError, PageOfEvents};

pub(crate) use reorg_counter::ReorgCounter;

pub use transaction::TransactionData;
pub use transaction::TransactionStatus;

pub use trie::{Node, NodeRef, StoredNode, TrieUpdate};

use pathfinder_common::{BlockNumber, TransactionHash};

use pathfinder_common::transaction::Transaction as StarknetTransaction;

type PooledConnection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;

pub struct Connection {
    connection: PooledConnection,
    bloom_filter_cache: Arc<crate::bloom::Cache>,
    prune_merkle_tries: bool,
}

impl Connection {
    pub(crate) fn new(
        connection: PooledConnection,
        bloom_filter_cache: Arc<crate::bloom::Cache>,
        prune_merkle_tries: bool,
    ) -> Self {
        Self {
            connection,
            bloom_filter_cache,
            prune_merkle_tries,
        }
    }

    pub fn transaction(&mut self) -> anyhow::Result<Transaction<'_>> {
        let tx = self.connection.transaction()?;
        Ok(Transaction {
            transaction: tx,
            bloom_filter_cache: self.bloom_filter_cache.clone(),
            trie_prune_mode: if self.prune_merkle_tries {
                TriePruneMode::Prune { num_blocks_kept: 0 }
            } else {
                TriePruneMode::Archive
            },
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
            trie_prune_mode: if self.prune_merkle_tries {
                TriePruneMode::Prune { num_blocks_kept: 0 }
            } else {
                TriePruneMode::Archive
            },
        })
    }
}

pub struct Transaction<'inner> {
    transaction: rusqlite::Transaction<'inner>,
    bloom_filter_cache: Arc<crate::bloom::Cache>,
    trie_prune_mode: TriePruneMode,
}

#[derive(Debug, Clone, Copy)]
pub enum TriePruneMode {
    /// Keep all merkle trie history.
    Archive,
    /// Prune merkle trie history. Only keep the last few blocks, as well as the lastest block.
    Prune { num_blocks_kept: u64 },
}

type TransactionWithReceipt = (
    StarknetTransaction,
    Receipt,
    Vec<pathfinder_common::event::Event>,
    BlockNumber,
);

type TransactionDataForBlock = (StarknetTransaction, Receipt, Vec<Event>);

type EventsForBlock = (TransactionHash, Vec<Event>);

impl<'inner> Transaction<'inner> {
    // The implementations here are intentionally kept as simple wrappers. This lets the real implementations
    // be kept in separate files with more reasonable LOC counts and easier test oversight.

    fn inner(&self) -> &rusqlite::Transaction<'_> {
        &self.transaction
    }

    pub fn commit(self) -> anyhow::Result<()> {
        Ok(self.transaction.commit()?)
    }
}
