/// This migration adds the nonce column to the `contract_states` table for the starknet 0.10 update.
///
/// The column gets a default value of zero for old rows which is the correct value for versions pre 0.10.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tx.execute(
        r"ALTER TABLE contract_states ADD COLUMN nonce 
BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'",
        [],
    )
    .context("Adding 'nonce' column to 'contract_states'")?;

    Ok(())
}
