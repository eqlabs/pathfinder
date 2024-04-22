use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use rusqlite::params;

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Re-compressing starknet_transactions");

    let mut transformers = Vec::new();
    let (insert_tx, insert_rx) = mpsc::channel();
    let (transform_tx, transform_rx) =
        flume::unbounded::<(Vec<u8>, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>)>();
    for _ in 0..thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
    {
        let insert_tx = insert_tx.clone();
        let transform_rx = transform_rx.clone();
        let mut tx_compressor = zstd::bulk::Compressor::with_prepared_dictionary(
            &crate::connection::transaction::ZSTD_TX_ENCODER_DICTIONARY,
        )?;
        let mut receipt_compressor = zstd::bulk::Compressor::with_prepared_dictionary(
            &crate::connection::transaction::ZSTD_RECEIPT_ENCODER_DICTIONARY,
        )?;
        let mut events_compressor = zstd::bulk::Compressor::with_prepared_dictionary(
            &crate::connection::transaction::ZSTD_EVENTS_ENCODER_DICTIONARY,
        )?;
        let transformer = thread::spawn(move || {
            for (hash, idx, block_number, transaction, receipt, events) in transform_rx.iter() {
                let transaction = zstd::decode_all(transaction.as_slice())
                    .context("Decompressing transaction")
                    .unwrap();
                let receipt = zstd::decode_all(receipt.as_slice())
                    .context("Decompressing receipt")
                    .unwrap();
                let events = zstd::decode_all(events.as_slice())
                    .context("Decompressing events")
                    .unwrap();

                let transaction = tx_compressor
                    .compress(&transaction)
                    .context("Compressing transaction")
                    .unwrap();
                let receipt = receipt_compressor
                    .compress(&receipt)
                    .context("Compressing receipt")
                    .unwrap();
                let events = events_compressor
                    .compress(&events)
                    .context("Compressing events")
                    .unwrap();

                // Store the updated values.
                if let Err(err) =
                    insert_tx.send((hash, idx, block_number, transaction, receipt, events))
                {
                    panic!("Failed to send transaction: {:?}", err);
                }
            }
        });
        transformers.push(transformer);
    }

    let mut progress_logged = Instant::now();
    const LOG_RATE: Duration = Duration::from_secs(10);

    let count = tx.query_row("SELECT COUNT(*) FROM starknet_transactions", [], |row| {
        row.get::<_, i64>(0)
    })?;
    tx.execute(
        r"
        CREATE TABLE starknet_transactions_new (
            hash         BLOB PRIMARY KEY,
            idx          INTEGER NOT NULL,
            block_number INTEGER NOT NULL,
            tx           BLOB,
            receipt      BLOB,
            events       BLOB
        )",
        [],
    )
    .context("Creating starknet_transactions_new table")?;
    let mut query_stmt = tx.prepare(
        r"
        SELECT hash, idx, block_number, tx, receipt, events FROM starknet_transactions
        ",
    )?;
    let mut insert_stmt = tx.prepare(
        r"INSERT INTO starknet_transactions_new (hash, idx, block_number, tx, receipt, events)
                                         VALUES (?, ?, ?, ?, ?, ?)",
    )?;
    const BATCH_SIZE: usize = 10_000;
    let mut rows = query_stmt.query([])?;
    let mut progress = 0;

    let mut original_size = 0usize;
    let mut new_size = 0usize;

    loop {
        let mut batch_size = 0;
        for _ in 0..BATCH_SIZE {
            match rows.next() {
                Ok(Some(row)) => {
                    let hash = row.get_ref_unwrap("hash").as_blob()?;
                    let idx = row.get_ref_unwrap("idx").as_i64()?;
                    let block_number = row.get_ref_unwrap("block_number").as_i64()?;
                    let transaction = row.get_ref_unwrap("tx").as_blob()?;
                    let receipt = row.get_ref_unwrap("receipt").as_blob()?;
                    let events = row.get_ref_unwrap("events").as_blob()?;

                    original_size += transaction.len() + receipt.len() + events.len();

                    transform_tx
                        .send((
                            hash.to_vec(),
                            idx,
                            block_number,
                            transaction.to_vec(),
                            receipt.to_vec(),
                            events.to_vec(),
                        ))
                        .context("Sending transaction to transformer")?;
                    batch_size += 1;
                }
                Ok(None) => break,
                Err(err) => return Err(err.into()),
            }
        }
        for _ in 0..batch_size {
            if progress % 1000 == 0 && progress_logged.elapsed() > LOG_RATE {
                progress_logged = Instant::now();
                tracing::info!(
                    "Migrating transactions: {:.2}%",
                    (progress as f64 / count as f64) * 100.0
                );
            }
            let (hash, idx, block_number, transaction, receipt, events) = insert_rx.recv()?;
            new_size += transaction.len() + receipt.len() + events.len();

            insert_stmt.execute(params![
                hash,
                idx,
                block_number,
                transaction,
                receipt,
                events
            ])?;
            progress += 1;
        }
        if batch_size < BATCH_SIZE {
            // This was the last batch.
            break;
        }
    }

    drop(insert_tx);
    drop(transform_tx);

    // Ensure that all transformers have finished successfully.
    for transformer in transformers {
        transformer.join().unwrap();
    }

    tracing::info!(%original_size, %new_size, "Re-compression done");

    tracing::info!("Dropping old starknet_transactions table");
    tx.execute("DROP TABLE starknet_transactions", [])?;
    tracing::info!("Renaming starknet_transactions_new to starknet_transactions");
    tx.execute(
        "ALTER TABLE starknet_transactions_new RENAME TO starknet_transactions",
        [],
    )
    .context("Renaming starknet_transactions_new to starknet_transactions")?;
    tracing::info!("Creating block_number index on starknet_transactions");
    tx.execute(
        "CREATE INDEX starknet_transactions_block_number ON starknet_transactions(block_number)",
        [],
    )
    .context("Creating index on block numbers")?;
    Ok(())
}
