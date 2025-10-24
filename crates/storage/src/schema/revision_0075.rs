use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Creating consensus proposals table");

    tx.execute(
        r"CREATE TABLE IF NOT EXISTS consensus_proposals (
            height      INTEGER NOT NULL,
            round       INTEGER NOT NULL,
            proposer    BLOB NOT NULL,
            parts       BLOB NOT NULL,
            UNIQUE(height, round, proposer)
        )",
        [],
    )
    .context("Creating consensus_proposals table")?;

    Ok(())
}
