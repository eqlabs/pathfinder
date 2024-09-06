use anyhow::Context;
use pathfinder_common::L1ToL2MessageLog;
use primitive_types::H256;

use super::Transaction;
use crate::prelude::*;

impl Transaction<'_> {
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

}
