use anyhow::Context;
use rusqlite::{named_params, Transaction};

/// This migration fixes event addresses. Events were incorrectly stored using the transaction's
/// contract address instead of the event's `from_address`.
pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    let todo: usize = transaction
        .query_row("SELECT count(1) FROM starknet_transactions", [], |r| {
            r.get(0)
        })
        .context("Count rows in starknet transactions table")?;

    if todo == 0 {
        return Ok(());
    }

    tracing::info!(
        num_transactions=%todo,
        "Decompressing transactions and fixing event addresses, this may take a while.",
    );

    let prepping_started = std::time::Instant::now();

    transaction
        .execute("DROP INDEX starknet_events_from_address", [])
        .context("Failed to drop the index before updates")?;

    // the inner loop of the migration does a lot of updates based on transaction_hash and the
    // index, so there should be an index for that, and it's unique since it can be.
    transaction
        .execute(
            "CREATE UNIQUE INDEX temp_starknet_events_q ON starknet_events (transaction_hash, idx)",
            [],
        )
        .context("create temporary index")?;

    transaction
        .execute("DROP TRIGGER starknet_events_au", [])
        .context("Failed to drop after update trigger")?;

    let prepping_time = prepping_started.elapsed();

    tracing::info!(?prepping_time, "Migration preparations complete");

    let mut stmt = transaction
        .prepare("SELECT hash, receipt FROM starknet_transactions")
        .context("Prepare transaction query")?;
    let mut rows = stmt.query([])?;

    let mut update = transaction.prepare(
        r"UPDATE starknet_events
             SET from_address=:from_address
           WHERE idx=:idx AND transaction_hash=:transaction_hash",
    )?;

    let mut processed_rows = 0;
    let start_of_run = std::time::Instant::now();
    let mut start_of_batch = start_of_run;
    let batch_size = (todo / 11).max(10_000);
    let mut decompression_time = std::time::Duration::default();
    let mut parsing_time = std::time::Duration::default();

    while let Some(r) = rows.next()? {
        let transaction_hash = r.get_ref_unwrap("hash").as_blob()?;
        let receipt = r.get_ref_unwrap("receipt").as_blob()?;
        let decompression_started = std::time::Instant::now();
        let receipt = zstd::decode_all(receipt).context("Decompress receipt")?;
        decompression_time += decompression_started.elapsed();

        let parsing_started = std::time::Instant::now();
        let receipt: LightReceipt =
            serde_json::from_slice(&receipt).context("Deserializing transaction receipt")?;
        parsing_time += parsing_started.elapsed();

        receipt.events.into_iter().enumerate().try_for_each(
            |(idx, event)| -> anyhow::Result<_> {
                update
                    .execute(named_params![
                        ":idx": idx,
                        ":transaction_hash": transaction_hash,
                        ":from_address": event.from_address,
                    ])
                    .context("Insert event data into events table")?;

                Ok(())
            },
        )?;

        processed_rows += 1;

        if processed_rows % batch_size == 0 {
            let now = std::time::Instant::now();
            let total_elapsed = now - start_of_run;
            let batch_elapsed = now - start_of_batch;

            let total_per_row = total_elapsed.div_f64(processed_rows as f64);
            let batch_per_row = batch_elapsed.div_f64(batch_size as f64);

            // this is non-scientific, but perhaps the latest helps? seems to be very much off until 75% when divided by 2, 50% when divided by 1.5
            let est_per_row = (total_per_row + batch_per_row).div_f64(1.5);
            let remaining = est_per_row * ((todo - processed_rows) as u32);

            tracing::info!(
                "Fixing {:.1}% complete, estimated remaining {remaining:?}",
                (100.0 * processed_rows as f64 / todo as f64)
            );
            start_of_batch = now;
        }
    }

    tracing::info!(
        ?decompression_time,
        ?parsing_time,
        total_time=?start_of_run.elapsed(),
        "Fixing complete, restoring"
    );

    let recreate_started = std::time::Instant::now();

    transaction
        .execute("DROP INDEX temp_starknet_events_q", [])
        .context("Failed to drop temporary index")?;

    transaction
        .execute(
            "CREATE INDEX starknet_events_from_address ON starknet_events(from_address)",
            [],
        )
        .context("Failed to recreate index")?;
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
        .context("Failed to recreate trigger")?;

    let recreation_time = recreate_started.elapsed();

    tracing::info!(?recreation_time, "Recreation complete");

    Ok(())
}

/// Real receipt json has a bunch of fields which we don't need
#[derive(serde::Deserialize)]
struct LightReceipt {
    events: Vec<LightEvent>,
}

#[derive(serde::Deserialize)]
struct LightEvent {
    from_address: pathfinder_common::ContractAddress,
}
