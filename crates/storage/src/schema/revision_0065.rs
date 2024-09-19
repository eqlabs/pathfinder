use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Adding table(s) to store L1->L2 message data");

    tx.execute_batch(
        r"
        CREATE TABLE l1_to_l2_message_logs (
            msg_hash   BLOB NOT NULL PRIMARY KEY,
            l1_block_number INTEGER,
            l1_tx_hash BLOB,
            l2_tx_hash BLOB
        );",
    )
    .context("Adding table to store L1 to L2 message data")?;

    tx.execute_batch(
        r"
        CREATE TABLE l1_handler_txs (
            l1_block_number INTEGER NOT NULL,
            l1_tx_hash BLOB NOT NULL,
            l2_tx_hash BLOB NOT NULL
        );
        CREATE INDEX idx_l1_handler_txs_l1_tx_hash ON l1_handler_txs(l1_tx_hash);
        ",
    )
    .context("Adding table and index to store L1 handler tx data")?;

    Ok(())
}
