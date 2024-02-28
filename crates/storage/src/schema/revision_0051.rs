use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
        CREATE TABLE state_update_stats (
            block_number INTEGER NOT NULL PRIMARY KEY,
            num_storage_diffs INTEGER NOT NULL,
            num_nonce_updates INTEGER NOT NULL,
            num_declared_classes INTEGER NOT NULL,
            num_deployed_contracts INTEGER NOT NULL
        );
    ",
    )
    .context("Creating state update stats table")
}
