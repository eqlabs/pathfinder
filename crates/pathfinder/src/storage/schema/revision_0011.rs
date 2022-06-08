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

    let mut stmt = transaction
        .prepare("SELECT hash, receipt FROM starknet_transactions")
        .context("Prepare transaction query")?;
    let mut rows = stmt.query([])?;

    while let Some(r) = rows.next()? {
        let transaction_hash = r.get_ref_unwrap("hash").as_blob()?;
        let receipt = r.get_ref_unwrap("receipt").as_blob()?;
        let receipt = zstd::decode_all(receipt).context("Decompress receipt")?;
        let receipt: transaction::Receipt =
            serde_json::de::from_slice(&receipt).context("Deserializing transaction receipt")?;

        receipt.events.into_iter().enumerate().try_for_each(
            |(idx, event)| -> anyhow::Result<_> {
                transaction
                    .execute(
                        r"UPDATE starknet_events 
                            SET from_address=:from_address
                            WHERE idx=:idx AND transaction_hash=:transaction_hash",
                        named_params![
                            ":idx": idx,
                            ":transaction_hash": transaction_hash,
                            ":from_address": &event.from_address.0.as_be_bytes()[..],
                        ],
                    )
                    .context("Insert event data into events table")?;

                Ok(())
            },
        )?;
    }

    Ok(PostMigrationAction::None)
}
