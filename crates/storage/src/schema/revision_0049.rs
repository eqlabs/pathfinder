use anyhow::Context;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tx.execute_batch(
        r"
ALTER TABLE block_headers ADD COLUMN eth_l1_data_gas_price BLOB DEFAULT NULL;
ALTER TABLE block_headers ADD COLUMN strk_l1_data_gas_price BLOB DEFAULT NULL;
",
    )
    .context("Creating block_signatures table")?;

    Ok(())
}
