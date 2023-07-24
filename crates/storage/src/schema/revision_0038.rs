use anyhow::Context;

/// This migration removes the event key FTS5 table for v0.2 RPC.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Removing event event data for RPC v0.2, this may take some time.");
    tx.execute_batch(
        "
DROP TRIGGER starknet_events_ad;
DROP TRIGGER starknet_events_ai;
DROP TRIGGER starknet_events_au;
DROP TABLE  starknet_events_keys;
    ",
    )
    .context("Dropping v0.2 events FTS5 data and triggers")
}
