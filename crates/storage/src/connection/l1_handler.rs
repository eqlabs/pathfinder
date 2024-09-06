use anyhow::Context;
use pathfinder_common::TransactionHash;
use primitive_types::H256;

use super::Transaction;
use crate::prelude::*;

impl Transaction<'_> {
    pub fn insert_l1_handler_tx(
        &self,
        l1_tx_hash: &H256,
        l2_tx_hash: &TransactionHash,
    ) -> anyhow::Result<()> {
        self.inner()
            .execute(
                "INSERT INTO l1_handler_txs (l1_tx_hash, l2_tx_hash) VALUES (?, ?)",
                params![&l1_tx_hash.as_bytes(), l2_tx_hash,],
            )
            .context("Inserting L1 handler tx")?;
        Ok(())
    }
}
