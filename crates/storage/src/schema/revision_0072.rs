use anyhow::Context;
use rusqlite::params;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Changing l2_gas_price default value");

    tx.execute(
        "UPDATE block_headers SET eth_l2_gas_price = ? WHERE eth_l2_gas_price = ?",
        params![1, 0],
    )
    .context("Updating block_headers.eth_l2_gas_price")?;
    tx.execute(
        "UPDATE block_headers SET strk_l2_gas_price = ? WHERE strk_l2_gas_price = ?",
        params![1, 0],
    )
    .context("Updating block_headers.strk_l2_gas_price")?;

    Ok(())
}
