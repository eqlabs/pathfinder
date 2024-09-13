use anyhow::Context;
use pathfinder_common::{L1ToL2MessageLog, TransactionHash};
use pathfinder_crypto::Felt;
use primitive_types::H256;

use super::Transaction;
use crate::prelude::*;

impl Transaction<'_> {
    /// Inserts an L1 to L2 message log into the database.
    pub fn insert_l1_to_l2_message_log(&self, message: &L1ToL2MessageLog) -> anyhow::Result<()> {
        self.inner()
            .execute(
                "INSERT INTO l1_to_l2_message_logs (msg_hash, l1_tx_hash, l2_tx_hash) VALUES (?, \
                 ?, ?)",
                params![
                    &message.message_hash.as_bytes(),
                    &message.l1_tx_hash.map(|h| h.as_bytes().to_vec()),
                    &message.l2_tx_hash.map(|h| h.0.as_be_bytes().to_vec()),
                ],
            )
            .context("Inserting L1 to L2 message log")?;
        Ok(())
    }

    /// Fetches the L1 and L2 tx hash for a given message hash and, if found,
    /// removes the entry from the database.
    pub fn fetch_and_remove_l1_to_l2_message_log(
        &self,
        message_hash: &H256,
    ) -> anyhow::Result<(Option<H256>, Option<TransactionHash>)> {
        let mut stmt = self
            .inner()
            .prepare_cached(
                "SELECT l1_tx_hash, l2_tx_hash FROM l1_to_l2_message_logs WHERE msg_hash = ?",
            )
            .context("Preparing fetch L1 to L2 message log statement")?;

        let raw_data = stmt
            .query_row(params![&message_hash.as_bytes().to_vec()], |row| {
                Ok((
                    row.get::<_, Option<Vec<u8>>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                ))
            })
            .optional()
            .context("Querying L1 to L2 message log")?;

        if let Some(data) = raw_data {
            self.inner()
                .execute(
                    "DELETE FROM l1_to_l2_message_logs WHERE msg_hash = ?",
                    params![&message_hash.as_bytes().to_vec()],
                )
                .context("Deleting L1 to L2 message log")?;

            Ok((
                data.0.map(|b| H256::from_slice(&b)),
                data.1.map(|b| {
                    TransactionHash(Felt::from_be_slice(&b).expect("Invalid transaction hash"))
                }),
            ))
        } else {
            Ok((None, None))
        }
    }
}
