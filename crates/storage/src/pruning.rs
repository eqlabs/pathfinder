use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{BlockHeader, BlockNumber};
use tokio::sync::broadcast::Receiver;

use crate::{BlockId, Storage, Transaction};

/// Runs a task that prunes the blockchain history when the number of blocks
/// exceeds a certain threshold.
pub fn run_blockchain_pruning(
    prune_storage: Storage,
    block_header_rx: Receiver<Arc<BlockHeader>>,
    num_blocks_kept: u64,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    pub async fn blockchain_pruning(
        prune_storage: Storage,
        mut block_header_rx: Receiver<Arc<BlockHeader>>,
        num_blocks_kept: u64,
    ) -> anyhow::Result<()> {
        let block_threshold = match num_blocks_kept {
            0 => 1,
            n => std::cmp::min(3 * n / 2, 1000),
        };
        tracing::info!(history_kept=%num_blocks_kept, "Blockchain pruning enabled");

        let mut block_cnt = 0;

        loop {
            let header = block_header_rx.recv().await?;
            block_cnt += 1;

            if block_cnt >= block_threshold {
                block_cnt = 0;
                tokio::task::block_in_place(|| {
                    prune_storage
                        .connection()
                        .context("Creating database connection for blockchain pruning")?
                        .with_retry()
                        .context("Enabling retries for database connection")?
                        .transaction_with_behavior(
                            // Avoid contention with the transaction that writes the block header
                            // data.
                            crate::TransactionBehavior::Immediate,
                        )
                        .context("Creating database transaction for blockchain pruning")?
                        .prune_blockchain(header.number, num_blocks_kept)
                        .context("Pruning blockchain history")
                })?;
            }
        }
    }

    util::task::spawn(blockchain_pruning(
        prune_storage,
        block_header_rx,
        num_blocks_kept,
    ))
}

impl Transaction<'_> {
    /// Performs pruning of the blockchain history. Last kept block's number is
    /// `latest` - `num_blocks_kept`.
    pub fn prune_blockchain(self, latest: BlockNumber, num_blocks_kept: u64) -> anyhow::Result<()> {
        let Some(oldest) = latest.checked_sub(num_blocks_kept) else {
            return Ok(());
        };

        let start = std::time::Instant::now();
        tracing::info!(last_kept=%oldest, "Running blockchain pruning");
        self.delete_transactions_before(oldest)?;
        self.delete_transaction_hashes_before(oldest)?;
        tracing::debug!(last_kept=%oldest, elapsed=?start.elapsed(), "Blockchain pruning done");
        self.commit()
    }

    pub fn prune_blockchain_on_startup(self, num_blocks_kept: u64) -> anyhow::Result<()> {
        let Some(latest) = self
            .block_number(BlockId::Latest)
            .context("Getting latest block number")?
        else {
            // Nothing to prune.
            return Ok(());
        };

        self.prune_blockchain(latest, num_blocks_kept)
    }
}
