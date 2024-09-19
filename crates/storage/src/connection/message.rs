use anyhow::Context;
use pathfinder_common::{L1ToL2MessageLog, TransactionHash};
use pathfinder_crypto::Felt;
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
                    &message.message_hash.as_bytes(),
                    &message.l1_block_number,
                    &message.l1_tx_hash.map(|h| h.as_bytes().to_vec()),
                    &message.l2_tx_hash.map(|h| h.0.as_be_bytes().to_vec()),
                ],
            )
            .context("Upserting L1 to L2 message log")?;

        if let Some(l2_tx_hash) = &message.l2_tx_hash {
            tracing::trace!(
                "Inserted L1 to L2 message log with L2 tx hash: {:?}",
                l2_tx_hash
            );
        } else if let Some(l1_tx_hash) = &message.l1_tx_hash {
            tracing::trace!(
                "Inserted L1 to L2 message log with L1 tx hash: {:?}",
                l1_tx_hash
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
                    row.get::<_, Option<u64>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            })
            .optional()
            .context("Querying L1 to L2 message log")?;

        if let Some(data) = raw_data {
            let debug_tx_str = match (&data.1, &data.2) {
                (Some(_), None) => "[L1, X]",
                (None, Some(_)) => "[X, L2]",
                _ => "N/A",
            };
            tracing::trace!(
                "Fetched (and found: {}) an L1 to L2 message log for {:?}",
                debug_tx_str,
                message_hash
            );

            Ok(Some(L1ToL2MessageLog {
                message_hash: *message_hash,
                l1_block_number: data.0,
                l1_tx_hash: data.1.map(|b| H256::from_slice(&b)),
                l2_tx_hash: data.2.map(|b| {
                    TransactionHash(Felt::from_be_slice(&b).expect("Invalid transaction hash"))
                }),
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

        tracing::trace!("Removed L1 to L2 message log: {:?}", message_hash);
        Ok(())
    }
}
