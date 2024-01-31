use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Dropping CASM compiler version information");

    tx.execute_batch(
        r"
        ALTER TABLE casm_definitions DROP COLUMN compiler_version_id;
        DROP TABLE casm_compiler_versions;
        ",
    )
    .context("Dropping CASM compiler version table")?;

    Ok(())
}
