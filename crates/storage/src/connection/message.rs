use anyhow::Context;
use pathfinder_common::L1ToL2MessageLog;
use primitive_types::H256;

use super::Transaction;
use crate::prelude::*;

impl Transaction<'_> {
    /// Inserts an L1 to L2 message log into the database.
    pub fn insert_l1_to_l2_message_log(&self, message: &L1ToL2MessageLog) -> anyhow::Result<()> {
        self.inner()
            .execute(
                "INSERT INTO l1_to_l2_message_logs (msg_hash, l1_tx_hash) VALUES (?, ?)",
                params![
                    &message.message_hash.as_bytes(),
                    &message.l1_tx_hash.as_bytes(),
                ],
            )
            .context("Inserting L1 to L2 message log")?;
        Ok(())
    }

    /// Fetches the L1 tx hash for a given message hash and removes the entry
    /// from the database.
    pub fn fetch_and_remove_l1_to_l2_message_log(
        &self,
        message_hash: &H256,
    ) -> anyhow::Result<Option<H256>> {
        let mut stmt = self
            .inner()
            .prepare_cached("SELECT l1_tx_hash FROM l1_to_l2_message_logs WHERE msg_hash = ?")
            .context("Preparing fetch L1 to L2 message log statement")?;

        let message = stmt
            .query_row(params![&message_hash.as_bytes().to_vec()], |row| {
                Ok(H256::from_slice(&row.get::<_, Vec<u8>>(0)?))
            })
            .optional()
            .context("Querying L1 to L2 message log")?;

        if message.is_some() {
            self.inner()
                .execute(
                    "DELETE FROM l1_to_l2_message_logs WHERE msg_hash = ?",
                    params![&message_hash.as_bytes().to_vec()],
                )
                .context("Deleting L1 to L2 message log")?;
        }

        Ok(message)
    }
}
