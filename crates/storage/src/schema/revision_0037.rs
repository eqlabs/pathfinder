use anyhow::Context;

/// Adds the `execution_status` integer column to the `starknet_transactions` table. The column
/// is an enum where existing rows get assigned 0 == SUCCESS, and reverted txns will get assigned 1
/// for reverted.
///
/// Important to note that this was implemented before reverted txns were introduced i.e. all txns before
/// this time were automatically succesful.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute(
        r"
ALTER TABLE starknet_transactions
    ADD COLUMN execution_status INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .context("Adding execution_status column to transactions table")?;

    Ok(())
}
