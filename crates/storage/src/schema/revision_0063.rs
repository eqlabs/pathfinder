use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Adding table(s) to store L1->L2 message data");

    tx.execute_batch(
        r"
        CREATE TABLE l1_to_l2_message_logs (
            msg_hash   BLOB NOT NULL PRIMARY KEY,
            l1_tx_hash BLOB NOT NULL
        );",
    )
    .context("Adding table to store L1 to L2 message data")?;

    Ok(())
}
