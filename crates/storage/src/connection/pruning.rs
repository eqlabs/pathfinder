//! Blockchain history pruning is a feature that can be enabled to limit the
//! number of blocks stored in the database, thus keeping the size of the
//! database in check. The latest block is always stored.
//!
//! Database tables that are subject to pruning are:
//! - `transactions`
//! - `transaction_hashes`
//! - `block_headers`
//! - `canonical_blocks`
//! - `block_signatures`
//! - `contract_updates` (a row can be pruned if there is another row with the
//!   same `contract_address` and a higher `block_number`)
//! - `nonce_updates` (a row can be pruned if there is another row with the same
//!   `contract_address_id` and a higher `block_number`)
//! - `storage_updates` (a row can be pruned if there is another row with the
//!   same `contract_address_id`, same `storage_address_id` and a higher
//!   `block_number`)
//!
//! The number of blocks kept in the database is configurable but once chosen,
//! it cannot change until a new database is created. It is also forbidden to
//! enable pruning on a database that was created with it disabled (and vice
//! versa). These restrictions are there to make it possible to prune block and
//! (contract/nonce/storage) update data without breaking reorg handling.

use anyhow::Context;
use pathfinder_common::BlockNumber;

use super::Transaction;
use crate::prelude::{named_params, params, RowExt};
use crate::BlockId;

#[derive(Debug, Clone, Copy)]
pub enum BlockchainHistoryMode {
    /// Keep the entire blockchain history.
    Archive,
    /// Prune the blockchain history. Only keep the last `num_blocks_kept`
    /// blocks as well as the latest block.
    Prune { num_blocks_kept: u64 },
}

impl Transaction<'_> {
    /// Performs pruning of the blockchain history. Last kept block's number is
    /// `latest` - `num_blocks_kept`.
    pub fn prune_blockchain(
        &self,
        latest: BlockNumber,
        num_blocks_kept: u64,
    ) -> anyhow::Result<()> {
        let block_to_prune = latest
            .checked_sub(num_blocks_kept + 1)
            .expect("Blockchain pruning should not start before there are blocks to prune");

        tracing::info!(%block_to_prune, "Running blockchain pruning");
        let start = std::time::Instant::now();
        self.prune_transaction_data(block_to_prune)
            .context("Pruning transaction data")?;
        self.prune_block_data(block_to_prune)
            .context("Pruning block data")?;
        tracing::debug!(pruned_block=%block_to_prune, elapsed=?start.elapsed(), "Blockchain pruning done");

        Ok(())
    }

    fn prune_transaction_data(&self, block: BlockNumber) -> anyhow::Result<()> {
        let mut transaction_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM transactions
            WHERE block_number = ?
            ",
        )?;
        let mut transaction_hashes_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM transaction_hashes
            WHERE block_number = ?
            ",
        )?;
        transaction_stmt.execute(params![&block])?;
        transaction_hashes_stmt.execute(params![&block])?;

        Ok(())
    }

    fn prune_block_data(&self, block: BlockNumber) -> anyhow::Result<()> {
        let mut block_is_prunable_stmt = self.inner().prepare_cached(
            r"
            SELECT EXISTS (
                SELECT 1
                FROM block_headers
                WHERE number = ?
                AND NOT EXISTS (
                    SELECT 1
                    FROM contract_updates
                    WHERE block_number = block_headers.number
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM nonce_updates
                    WHERE block_number = block_headers.number
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM storage_updates
                    WHERE block_number = block_headers.number
                )
            ) AS has_no_updates
            ",
        )?;

        let prunable = block_is_prunable_stmt
            .query_row(params![&block], |row| row.get::<_, bool>(0))
            .context(format!("Checkig if block {block} is prunable"))?;

        // A block without any state update cannot make any other state updates
        // obsolete. Moreover, it can immediately be pruned since there are no updates
        // to make obsolete on it.
        if prunable {
            self.prune_block(&block)?;
            return Ok(());
        }

        let mut contract_updates_select_stmt = self.inner().prepare_cached(
            r"
            SELECT contract_address
            FROM contract_updates
            WHERE block_number = :last_kept_block
            ",
        )?;
        let mut nonce_updates_select_stmt = self.inner().prepare_cached(
            r"
            SELECT contract_address_id
            FROM nonce_updates
            WHERE block_number = :last_kept_block
            ",
        )?;
        let mut storage_updates_select_stmt = self.inner().prepare_cached(
            r"
            SELECT contract_address_id, storage_address_id
            FROM storage_updates
            WHERE block_number = :last_kept_block
            ",
        )?;
        let mut blocks_with_same_contract_update = self.inner().prepare_cached(
            r"
            SELECT block_number
            FROM contract_updates
            WHERE contract_address = ?
            AND block_number < ?
            ",
        )?;
        let mut blocks_with_same_nonce_update = self.inner().prepare_cached(
            r"
            SELECT block_number
            FROM nonce_updates
            WHERE contract_address_id = ?
            AND block_number < ?
            ",
        )?;
        let mut blocks_with_same_storage_update = self.inner().prepare_cached(
            r"
            SELECT block_number
            FROM storage_updates
            WHERE contract_address_id = ?
            AND storage_address_id = ?
            AND block_number < ?
            ",
        )?;
        let mut contract_updates_delete_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM contract_updates
            WHERE contract_address = ?
            AND block_number = ?
            ",
        )?;
        let mut nonce_updates_delete_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM nonce_updates
            WHERE contract_address_id = ?
            AND block_number = ?
            ",
        )?;
        let mut storage_updates_delete_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM storage_updates
            WHERE contract_address_id = ?
            AND storage_address_id = ?
            AND block_number = ?
            ",
        )?;

        // Only blocks that had updates deleted during this pruning run are worth
        // checking for deletion. This array will contain the block numbers of
        // such blocks.
        let mut blocks_with_removed_update = vec![];
        let last_kept_block = block + 1;

        // Find and delete the updates that are no longer needed.
        let contract_update_ids = contract_updates_select_stmt
            .query_map(
                named_params!(
                    ":last_kept_block": &last_kept_block,
                ),
                |row| row.get_contract_address(0),
            )
            .context("Querying contract_updates")?
            .collect::<Result<Vec<_>, _>>()?;
        let nonce_update_ids = nonce_updates_select_stmt
            .query_map(
                named_params! {
                    ":last_kept_block": &last_kept_block,
                },
                |row| row.get(0),
            )
            .context("Querying nonce_updates")?
            .collect::<Result<Vec<i64>, _>>()?;
        let storage_update_ids = storage_updates_select_stmt
            .query_map(
                named_params! {
                    ":last_kept_block": &last_kept_block,
                },
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .context("Querying storage_updates")?
            .collect::<Result<Vec<(i64, i64)>, _>>()?;
        for address in &contract_update_ids {
            let blocks_with_same_update = blocks_with_same_contract_update
                .query_map(params![address, &last_kept_block], |row| {
                    row.get_block_number(0)
                })
                .context("Querying blocks with same contract update")?
                .collect::<Result<Vec<_>, _>>()?;
            for block in blocks_with_same_update {
                contract_updates_delete_stmt
                    .execute(params![address, &block])
                    .context("Deleting storage updates")?;
                blocks_with_removed_update.push(block);
            }
        }
        for id in &nonce_update_ids {
            let blocks_with_same_update = blocks_with_same_nonce_update
                .query_map(params![id, &last_kept_block], |row| row.get_block_number(0))
                .context("Querying blocks with same nonce update")?
                .collect::<Result<Vec<_>, _>>()?;
            for block in blocks_with_same_update {
                nonce_updates_delete_stmt
                    .execute(params![id, &block])
                    .context("Deleting nonce updates")?;
                blocks_with_removed_update.push(block);
            }
        }
        for (contract_address_id, storage_address_id) in &storage_update_ids {
            let blocks_with_same_update = blocks_with_same_storage_update
                .query_map(
                    params![contract_address_id, storage_address_id, &last_kept_block],
                    |row| row.get_block_number(0),
                )
                .context("Querying blocks with same storage update")?
                .collect::<Result<Vec<_>, _>>()?;
            for block in blocks_with_same_update {
                storage_updates_delete_stmt
                    .execute(params![contract_address_id, storage_address_id, &block])
                    .context("Deleting storage updates")?;
                blocks_with_removed_update.push(block);
            }
        }

        // Delete blocks that do not have any updates left after deletion.
        for block in &blocks_with_removed_update {
            let prunable = block_is_prunable_stmt
                .query_row(params![block], |row| row.get::<_, bool>(0))
                .context(format!("Checkig if block {block} is prunable"))?;

            if prunable {
                self.prune_block(block)?;
            }
        }

        Ok(())
    }

    fn prune_block(&self, block: &BlockNumber) -> anyhow::Result<()> {
        let mut block_signatures_delete_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM block_signatures
            WHERE block_number = ?
            ",
        )?;
        let mut canonical_blocks_delete_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM canonical_blocks
            WHERE number = ?
            ",
        )?;
        let mut block_headers_delete_stmt = self.inner().prepare_cached(
            r"
            DELETE FROM block_headers
            WHERE number = ?
            ",
        )?;

        block_signatures_delete_stmt
            .execute(params![block])
            .context("Deleting block signatures")?;
        canonical_blocks_delete_stmt
            .execute(params![block])
            .context("Deleting block from canonical_blocks")?;
        block_headers_delete_stmt
            .execute(params![block])
            .context("Deleting block from block_headers")?;

        Ok(())
    }

    /// Checks if a block has been pruned.
    ///
    /// But not really, because there can be blocks that have had *some* of
    /// their data pruned but still have state updates tied to them that can't
    /// be pruned yet (otherwise `pruning_enabled` +
    /// [`block_exists`](Self::block_exists) would be the correct check). Still,
    /// in order to avoid providing misleading information, we consider those
    /// blocks as pruned.
    pub fn block_pruned(&self, block_id: BlockId) -> anyhow::Result<bool> {
        let BlockchainHistoryMode::Prune { num_blocks_kept } = self.blockchain_history_mode else {
            return Ok(false);
        };
        let Some(latest) = self.block_number(BlockId::Latest)? else {
            return Ok(false);
        };
        // If `latest` exists and the provided block doesn't, it has been pruned.
        let Some(block) = self.block_number(block_id)? else {
            return Ok(true);
        };

        Ok(latest
            .checked_sub(num_blocks_kept + 1)
            .is_some_and(|prune_point| block < prune_point))
    }
}
