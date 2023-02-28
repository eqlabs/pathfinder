/// This migration removes `abi` and `bytecode` columns from the `contract_code` table.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    use anyhow::Context;

    tx.execute("ALTER TABLE contract_code DROP COLUMN abi", [])
        .context("Removing column: contract_code.abi")?;
    tx.execute("ALTER TABLE contract_code DROP COLUMN bytecode", [])
        .context("Removing column: contract_code.bytecode")?;

    Ok(())
}
