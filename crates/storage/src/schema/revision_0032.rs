pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    let columns = &[
        "ethereum_transaction_hash",
        "ethereum_transaction_index",
        "ethereum_log_index",
        "ethereum_block_hash",
    ];

    for column in columns {
        let sql = format!("ALTER TABLE l1_state DROP COLUMN {}", column);
        tx.execute_batch(&sql)
            .context("Drop column from l1_state table")?;
    }

    Ok(())
}
