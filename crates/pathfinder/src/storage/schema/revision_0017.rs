use rusqlite::Transaction;

/// Adds `starknet_state_updates` table.
pub(crate) fn migrate(tx: &Transaction<'_>) -> anyhow::Result<()> {
    let mut query =
        tx.prepare("select name from sqlite_master where type = 'table' and name = ?")?;

    for tbl in ["tree_global", "tree_contracts"] {
        // in tests these tables are not yet initialized

        if !query.exists([tbl])? {
            continue;
        }

        tx.execute(&format!("DELETE FROM {tbl} WHERE length(data) = 0"), [])?;
    }

    Ok(())
}
