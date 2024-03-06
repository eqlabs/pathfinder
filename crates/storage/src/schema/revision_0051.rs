use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
        CREATE TABLE state_update_counts (
            block_number INTEGER NOT NULL PRIMARY KEY,
            storage_diffs INTEGER NOT NULL,
            nonce_updates INTEGER NOT NULL,
            declared_classes INTEGER NOT NULL,
            deployed_contracts INTEGER NOT NULL
        );
    ",
    )
    .context("Creating state update counts table")
}
