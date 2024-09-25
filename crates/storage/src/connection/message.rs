use anyhow::Context;
use pathfinder_common::{L1BlockNumber, L1ToL2MessageLog};
use primitive_types::H256;

use super::Transaction;
use crate::prelude::*;

impl Transaction<'_> {
    /// Inserts an L1 to L2 message log into the database.
    pub fn upsert_l1_to_l2_message_log(&self, message: &L1ToL2MessageLog) -> anyhow::Result<()> {
        self.inner()
            .execute(
                "INSERT OR REPLACE INTO l1_to_l2_message_logs (msg_hash, l1_block_number, \
                 l1_tx_hash, l2_tx_hash) VALUES (?, ?, ?, ?)",
                params![
                    &message.message_hash,
                    &message.l1_block_number,
                    &message.l1_tx_hash,
                    &message.l2_tx_hash,
                ],
            )
            .context("Upserting L1 to L2 message log")?;

        if let Some(l2_tx_hash) = &message.l2_tx_hash {
            tracing::debug!(
                %l2_tx_hash,
                "Inserted L1 to L2 message log with L2 tx hash"
            );
        } else if let Some(l1_tx_hash) = &message.l1_tx_hash {
            tracing::debug!(
                %l1_tx_hash,
                "Inserted L1 to L2 message log with L1 tx hash"
            );
        }

        Ok(())
    }

    /// Fetches the L1 and L2 tx hash for a given message hash and, if found,
    /// removes the entry from the database.
    pub fn fetch_l1_to_l2_message_log(
        &self,
        message_hash: &H256,
    ) -> anyhow::Result<Option<L1ToL2MessageLog>> {
        let mut stmt = self
            .inner()
            .prepare_cached(
                "SELECT l1_block_number, l1_tx_hash, l2_tx_hash FROM l1_to_l2_message_logs WHERE \
                 msg_hash = ?",
            )
            .context("Preparing fetch L1 to L2 message log statement")?;

        let raw_data = stmt
            .query_row(params![&message_hash.as_bytes().to_vec()], |row| {
                Ok((
                    row.get_optional_l1_block_number(0)?,
                    row.get_optional_l1_tx_hash(1)?,
                    row.get_optional_transaction_hash(2)?,
                ))
            })
            .optional()
            .context("Querying L1 to L2 message log")?;

        if let Some(data) = raw_data {
            tracing::trace!(
                %message_hash,
                l1_tx_hash=?data.1,
                l2_tx_hash=?data.2,
                "Fetched an L1 to L2 message log"
            );
            Ok(Some(L1ToL2MessageLog {
                message_hash: *message_hash,
                l1_block_number: data.0,
                l1_tx_hash: data.1,
                l2_tx_hash: data.2,
            }))
        } else {
            Ok(None)
        }
    }

    /// Removes an L1 to L2 message log from the database.
    pub fn remove_l1_to_l2_message_log(&self, message_hash: &H256) -> anyhow::Result<()> {
        self.inner()
            .execute(
                "DELETE FROM l1_to_l2_message_logs WHERE msg_hash = ?",
                params![&message_hash.as_bytes().to_vec()],
            )
            .context("Removing L1 to L2 message log")?;

        tracing::trace!(?message_hash, "Removed L1 to L2 message log");
        Ok(())
    }

    /// Fetches the highest L1 block number with an L1 handler tx.
    pub fn highest_block_with_l1_handler_tx(&self) -> anyhow::Result<Option<L1BlockNumber>> {
        let mut stmt = self.inner().prepare_cached(
            r"SELECT l1_block_number
        FROM l1_handler_txs
        ORDER BY l1_block_number DESC
        LIMIT 1",
        )?;
        stmt.query_row([], |row| row.get_l1_block_number(0))
            .optional()
            .context("Querying highest block with L1 handler txs")
    }
}
