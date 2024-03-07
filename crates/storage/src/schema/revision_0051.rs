use std::time::{Duration, Instant};

use anyhow::Context;
use rusqlite::{params, OptionalExtension};

use crate::params::RowExt;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Adding new columns to block_headers table");

    tx.execute_batch(
        r"ALTER TABLE block_headers ADD COLUMN storage_diffs_count INTEGER DEFAULT 0;
        ALTER TABLE block_headers ADD COLUMN nonce_updates_count INTEGER DEFAULT 0;
        ALTER TABLE block_headers ADD COLUMN declared_classes_count INTEGER DEFAULT 0;
        ALTER TABLE block_headers ADD COLUMN deployed_contracts_count INTEGER DEFAULT 0;
    ",
    )
    .context("Adding new columns to block_headers")?;

    let mut storage_diffs_query_statement =
        tx.prepare("SELECT COUNT(*) FROM storage_updates WHERE block_number = ?")?;

    let mut nonce_query_statement =
        tx.prepare("SELECT COUNT(*) FROM nonce_updates WHERE block_number = ?")?;

    let mut declared_query_statement =
        tx.prepare("SELECT COUNT(*) FROM class_definitions WHERE block_number = ?")?;

    let mut deployed_query_statement =
        tx.prepare("SELECT COUNT(*) FROM contract_updates WHERE block_number = ?")?;

    let mut insert_statement = tx.prepare(
        "INSERT INTO state_update_counts (block_number, storage_diffs, nonce_updates, declared_classes, deployed_contracts) VALUES (?, ?, ?, ?, ?)")?;

    let Some(highest_block) = tx
        .query_row(
            "SELECT number FROM canonical_blocks ORDER BY number DESC LIMIT 1",
            params![],
            |row| {
                let number = row.get_block_number(0)?;
                Ok(number)
            },
        )
        .optional()?
    else {
        return Ok(());
    };

    let mut progress_logged = Instant::now();
    const LOG_RATE: Duration = Duration::from_secs(10);

    for block_number in 0..=highest_block.get() {
        if block_number % 1000 == 0 && progress_logged.elapsed() > LOG_RATE {
            tracing::debug!(%block_number, "Processing events");
            progress_logged = Instant::now();
        }

        let storage_diffs = storage_diffs_query_statement
            .query_row(params![block_number], |row| row.get::<_, i64>(0))
            .optional()?
            .unwrap_or(0);

        let nonce_updates = nonce_query_statement
            .query_row(params![block_number], |row| row.get::<_, i64>(0))
            .optional()?
            .unwrap_or(0);

        let declared_classes = declared_query_statement
            .query_row(params![block_number], |row| row.get::<_, i64>(0))
            .optional()?
            .unwrap_or(0);

        let deployed_contracts = deployed_query_statement
            .query_row(params![block_number], |row| row.get::<_, i64>(0))
            .optional()?
            .unwrap_or(0);

        insert_statement.execute(params![
            &block_number,
            &storage_diffs,
            &nonce_updates,
            &declared_classes,
            &deployed_contracts
        ])?;
    }

    Ok(())
}
