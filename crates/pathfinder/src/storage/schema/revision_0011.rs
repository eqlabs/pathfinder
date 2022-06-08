use crate::{sequencer::reply::transaction, storage::schema::PostMigrationAction};

use anyhow::Context;
use rusqlite::{named_params, Transaction};

/// This migration fixes event addresses. Events were incorrectly stored using the transaction's
/// contract address instead of the event's `from_address`.
pub(crate) fn migrate(transaction: &Transaction) -> anyhow::Result<PostMigrationAction> {
    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_transactions", [], |r| {
            r.get(0)
        })
        .context("Count rows in starknet transactions table")?;

    if todo == 0 {
        return Ok(PostMigrationAction::None);
    }

    tracing::info!(
        num_transactions=%todo,
        "Decompressing transactions and fixing event addresses, this may take a while.",
    );

    transaction
        .execute("DROP INDEX starknet_events_from_address", [])
        .context("Failed to drop the index before updates")?;

    transaction
        .execute("DROP TRIGGER starknet_events_au", [])
        .context("Failed to drop after update trigger")?;

    let mut stmt = transaction
        .prepare("SELECT hash, receipt FROM starknet_transactions")
        .context("Prepare transaction query")?;
    let mut rows = stmt.query([])?;

    let mut update = transaction.prepare(
        r"UPDATE starknet_events
             SET from_address=:from_address
           WHERE idx=:idx AND transaction_hash=:transaction_hash",
    )?;

    while let Some(r) = rows.next()? {
        let transaction_hash = r.get_ref_unwrap("hash").as_blob()?;
        let receipt = r.get_ref_unwrap("receipt").as_blob()?;
        let receipt = zstd::decode_all(receipt).context("Decompress receipt")?;
        let receipt: transaction::Receipt =
            serde_json::de::from_slice(&receipt).context("Deserializing transaction receipt")?;

        receipt.events.into_iter().enumerate().try_for_each(
            |(idx, event)| -> anyhow::Result<_> {
                update
                    .execute(named_params![
                        ":idx": idx,
                        ":transaction_hash": transaction_hash,
                        ":from_address": &event.from_address.0.as_be_bytes()[..],
                    ])
                    .context("Insert event data into events table")?;

                Ok(())
            },
        )?;
    }

    transaction
        .execute(
            "CREATE INDEX starknet_events_from_address ON starknet_events(from_address)",
            [],
        )
        .context("Recreate index")?;
    transaction
        .execute(
            "CREATE TRIGGER starknet_events_au
            AFTER UPDATE ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
                VALUES (
                    'delete',
                    old.rowid,
                    old.keys
                );
                INSERT INTO starknet_events_keys(rowid, keys)
                VALUES (
                    new.rowid,
                    new.keys
                );
            END",
            [],
        )
        .context("Recreate trigger")?;

    Ok(PostMigrationAction::None)
}
