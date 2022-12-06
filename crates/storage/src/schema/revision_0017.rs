use anyhow::Context;
use rusqlite::Transaction;

/// Fixes starknet_events table schema.
///
/// Our revision 12 migration step had a bug: it didn't upgrade the events schema
/// in case the events table was empty, leaving us with a database where the
/// starknet_events table didn't have a stable rowid (via an INTEGER PRIMARY KEY).
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    if is_upgrade_required(transaction)? {
        super::revision_0012::migrate_events_schema(transaction)?
    }

    Ok(())
}

fn is_upgrade_required(transaction: &Transaction<'_>) -> anyhow::Result<bool> {
    let mut stmt = transaction
        .prepare("SELECT sql FROM sqlite_schema where tbl_name = 'starknet_events'")
        .context("Preparing statement")?;
    let mut rows = stmt.query([]).context("Executing query")?;
    // Unwrap is safe because the schema for this table obviously contains more than
    // zero SQL statements since we're guaranteed to have the starknet_events table.
    // The first statement of the schema for this table is the creation of the table
    // which could be missing the `id` primary key column.
    let contains_id_column = rows
        .next()?
        .unwrap()
        .get_ref_unwrap("sql")
        .as_str()?
        .contains("id INTEGER PRIMARY KEY NOT NULL");

    Ok(!contains_id_column)
}
