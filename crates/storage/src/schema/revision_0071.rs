//! Prior to this migration, [state update](crate::connection::state_update)
//! related tables have had FOREIGN KEY references with the ON DELETE CASCADE
//! action to the `canonical_blocks` table. The goal was to make purging blocks
//! easier by having a cascading delete effect on these tables when a row from
//! `canonical_blocks` is deleted.
//!
//! With the introduction of [blockchain pruning](crate::connection::pruning), a
//! need has arisen to delete block related table entries (including
//! `canonical_blocks`) independently of the state update tables. This was, of
//! course, not possible due to the aformentioned FOREIGN KEY references leading
//! to multiple workarounds and unnecessary complexity.
//!
//! This migration removes the FOREIGN KEY references to `canonical_blocks` from
//! the state update tables.

use anyhow::Context;
use pathfinder_common::BlockNumber;
use rusqlite::params;

const LOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

struct TableUpdate {
    table_name: &'static str,
    create_table_stmt: &'static str,
    transfer_fn: transfer::TransferFn,
    drop_and_rename_stmt: &'static str,
    create_indices_fn: indices::CreateIndicesFn,
}

pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Dropping FOREIGN KEY references from several state update related tables");

    let table_updates = [
        TableUpdate {
            table_name: "block_signatures",
            create_table_stmt: r"
                CREATE TABLE block_signatures_new(
                    block_number INTEGER REFERENCES block_headers(number) ON DELETE CASCADE,
                    signature_r  BLOB NOT NULL,
                    signature_s  BLOB NOT NULL
                );
            ",
            transfer_fn: transfer::block_signatures,
            drop_and_rename_stmt: r"
                DROP TABLE block_signatures;
                ALTER TABLE block_signatures_new RENAME TO block_signatures;
            ",
            create_indices_fn: indices::block_signatures,
        },
        TableUpdate {
            table_name: "class_definitions",
            create_table_stmt: r"
                CREATE TABLE class_definitions_new(
                    hash         BLOB PRIMARY KEY,
                    definition   BLOB,
                    block_number INTEGER REFERENCES block_headers(number) ON DELETE SET NULL
                );
            ",
            transfer_fn: transfer::class_definitions,
            drop_and_rename_stmt: r"
                DROP TABLE class_definitions;
                ALTER TABLE class_definitions_new RENAME TO class_definitions;
            ",
            create_indices_fn: indices::class_definitions,
        },
        TableUpdate {
            table_name: "contract_updates",
            create_table_stmt: r"
                CREATE TABLE contract_updates_new(
                    block_number     INTEGER NOT NULL,
                    contract_address BLOB NOT NULL,
                    class_hash       BLOB NOT NULL
                );
            ",
            transfer_fn: transfer::contract_updates,
            drop_and_rename_stmt: r"
                DROP TABLE contract_updates;
                ALTER TABLE contract_updates_new RENAME TO contract_updates;
            ",
            create_indices_fn: indices::contract_updates,
        },
        TableUpdate {
            table_name: "nonce_updates",
            create_table_stmt: r"
                CREATE TABLE nonce_updates_new(
                    block_number        INTEGER NOT NULL,
                    contract_address_id INTEGER NOT NULL REFERENCES contract_addresses(id),
                    nonce               BLOB NOT NULL
                );
            ",
            transfer_fn: transfer::nonce_updates,
            drop_and_rename_stmt: r"
                DROP TABLE nonce_updates;
                ALTER TABLE nonce_updates_new RENAME TO nonce_updates;
            ",
            create_indices_fn: indices::nonce_updates,
        },
        TableUpdate {
            table_name: "storage_updates",
            create_table_stmt: r"
                CREATE TABLE storage_updates_new(
                    block_number        INTEGER NOT NULL,
                    contract_address_id INTEGER NOT NULL REFERENCES contract_addresses(id),
                    storage_address_id  INTEGER NOT NULL REFERENCES storage_addresses(id),
                    storage_value       BLOB NOT NULL
                );
            ",
            transfer_fn: transfer::storage_updates,
            drop_and_rename_stmt: r"
                DROP TABLE storage_updates;
                ALTER TABLE storage_updates_new RENAME TO storage_updates;
            ",
            create_indices_fn: indices::storage_updates,
        },
    ];

    tracing::info!("Creating new tables");

    for update in &table_updates {
        tx.execute(update.create_table_stmt, [])
            .with_context(|| format!("Creating {}_new table", update.table_name))?;
    }

    let block_count = tx.query_row("SELECT COUNT(*) FROM block_headers", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let mut block_numbers = tx
        .prepare("SELECT number FROM block_headers ORDER BY number")
        .context("Preparing query block numbers statement")?;
    let mut block_numbers = block_numbers
        .query_map([], |row| {
            let block_number = row.get::<_, u64>(0)?;
            Ok(BlockNumber::new_or_panic(block_number))
        })
        .context("Querying block numbers")?;

    tracing::info!("Transferring data to the new tables");
    tracing::info!("Transferring: 0.00%");

    let mut last_logged = std::time::Instant::now();
    while let Some(block_number) = block_numbers.next().transpose()? {
        for update in &table_updates {
            (update.transfer_fn)(tx, block_number).with_context(|| {
                format!(
                    "Transferring data from {table} to {table}_new",
                    table = update.table_name
                )
            })?;
        }

        if last_logged.elapsed() > LOG_INTERVAL {
            tracing::info!(
                "Transferring: {:.2}%",
                (block_number.get() as f64 / block_count as f64) * 100.0
            );
            last_logged = std::time::Instant::now();
        }
    }
    tracing::info!("Transferring: 100.00%");

    tracing::info!("Dropping old tables, renaming new ones and re-creating indices");

    for update in &table_updates {
        tx.execute_batch(update.drop_and_rename_stmt)
            .with_context(|| {
                format!(
                    "Dropping {table} table and renaming {table}_new to {table}",
                    table = update.table_name
                )
            })?;

        (update.create_indices_fn)(tx)
            .with_context(|| format!("Creating indices for {} table", update.table_name))?;
    }

    tracing::info!("Dropping `canonical_blocks` table");

    tx.execute("DROP TABLE canonical_blocks", [])
        .context("Dropping canonical_blocks table")?;

    Ok(())
}

mod transfer {
    use super::*;

    pub(super) type TransferFn = fn(&rusqlite::Transaction<'_>, BlockNumber) -> anyhow::Result<()>;

    pub(super) fn block_signatures(
        tx: &rusqlite::Transaction<'_>,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        let mut select = tx
            .prepare_cached(
                r"
                SELECT block_number, signature_r, signature_s 
                FROM block_signatures 
                WHERE block_number = ?
                ",
            )
            .context("Preparing select statement")?;
        let mut insert = tx
            .prepare_cached(
                r"
                INSERT INTO block_signatures_new (block_number, signature_r, signature_s) 
                VALUES (?, ?, ?)
                ",
            )
            .context("Preparing insert statement")?;

        let (block_number, signature_r, signature_s) = select
            .query_row(params![&block_number.get()], |row| {
                let block_number: BlockNumber =
                    row.get::<_, u64>(0).map(BlockNumber::new_or_panic)?;
                let signature_r: Vec<u8> = row.get(1)?;
                let signature_s: Vec<u8> = row.get(2)?;

                Ok((block_number, signature_r, signature_s))
            })
            .context("Querying block signatures")?;

        insert
            .execute(params![block_number.get(), signature_r, signature_s])
            .context("Inserting block signatures")?;

        Ok(())
    }

    pub(super) fn class_definitions(
        tx: &rusqlite::Transaction<'_>,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        let mut select = tx
            .prepare_cached(
                r"
                SELECT hash, definition, block_number 
                FROM class_definitions
                WHERE block_number = ?
                ",
            )
            .context("Preparing select statement")?;
        let mut insert = tx
            .prepare_cached(
                r"
                INSERT INTO class_definitions_new (hash, definition, block_number) 
                VALUES (?, ?, ?)
            ",
            )
            .context("Preparing insert statement")?;

        let mut rows = select
            .query_map(params![&block_number.get()], |row| {
                let hash: Vec<u8> = row.get(0)?;
                let definition: Vec<u8> = row.get(1)?;
                let block_number: BlockNumber =
                    row.get::<_, u64>(2).map(BlockNumber::new_or_panic)?;

                Ok((hash, definition, block_number))
            })
            .context("Querying class definitions")?;

        while let Some((hash, definition, block_number)) = rows.next().transpose()? {
            insert
                .execute(params![hash, definition, block_number.get()])
                .context("Inserting class definitions")?;
        }

        Ok(())
    }

    pub(super) fn contract_updates(
        tx: &rusqlite::Transaction<'_>,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        let mut select = tx
            .prepare_cached(
                r"
                SELECT block_number, contract_address, class_hash 
                FROM contract_updates
                WHERE block_number = ?
                ",
            )
            .context("Preparing select statement")?;
        let mut insert = tx
            .prepare_cached(
                r"
                INSERT INTO contract_updates_new (block_number, contract_address, class_hash) 
                VALUES (?, ?, ?)
                ",
            )
            .context("Preparing insert statement")?;

        let mut rows = select
            .query_map(params![&block_number.get()], |row| {
                let block_number: BlockNumber =
                    row.get::<_, u64>(0).map(BlockNumber::new_or_panic)?;
                let contract_address: Vec<u8> = row.get(1)?;
                let class_hash: Vec<u8> = row.get(2)?;

                Ok((block_number, contract_address, class_hash))
            })
            .context("Querying contract updates")?;

        while let Some((block_number, contract_address, class_hash)) = rows.next().transpose()? {
            insert
                .execute(params![block_number.get(), contract_address, class_hash])
                .context("Inserting contract updates")?;
        }

        Ok(())
    }

    pub(super) fn nonce_updates(
        tx: &rusqlite::Transaction<'_>,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        let mut select = tx
            .prepare_cached(
                r"
                SELECT block_number, contract_address_id, nonce 
                FROM nonce_updates
                WHERE block_number = ?
                ",
            )
            .context("Preparing select statement")?;
        let mut insert = tx
            .prepare_cached(
                r"
                INSERT INTO nonce_updates_new (block_number, contract_address_id, nonce) 
                VALUES (?, ?, ?)
                ",
            )
            .context("Preparing insert statement")?;

        let mut rows = select
            .query_map(params![&block_number.get()], |row| {
                let block_number: BlockNumber =
                    row.get::<_, u64>(0).map(BlockNumber::new_or_panic)?;
                let contract_address_id: i64 = row.get(1)?;
                let nonce: Vec<u8> = row.get(2)?;

                Ok((block_number, contract_address_id, nonce))
            })
            .context("Querying nonce updates")?;

        while let Some((block_number, contract_address_id, nonce)) = rows.next().transpose()? {
            insert
                .execute(params![block_number.get(), contract_address_id, nonce])
                .context("Inserting nonce updates")?;
        }

        Ok(())
    }

    pub(super) fn storage_updates(
        tx: &rusqlite::Transaction<'_>,
        block_number: BlockNumber,
    ) -> anyhow::Result<()> {
        let mut select = tx
            .prepare_cached(
                r"
                SELECT block_number, contract_address_id, storage_address_id, storage_value 
                FROM storage_updates
                WHERE block_number = ?
                ",
            )
            .context("Preparing select statement")?;
        let mut insert = tx
            .prepare_cached(
                r"
                INSERT INTO storage_updates_new (block_number, contract_address_id, storage_address_id, storage_value) 
                VALUES (?, ?, ?, ?)
                ",
            )
            .context("Preparing insert statement")?;

        let mut rows = select
            .query_map(params![&block_number.get()], |row| {
                let block_number: BlockNumber =
                    row.get::<_, u64>(0).map(BlockNumber::new_or_panic)?;
                let contract_address_id: i64 = row.get(1)?;
                let storage_address_id: i64 = row.get(2)?;
                let storage_value: Vec<u8> = row.get(3)?;

                Ok((
                    block_number,
                    contract_address_id,
                    storage_address_id,
                    storage_value,
                ))
            })
            .context("Querying storage updates")?;

        while let Some((block_number, contract_address_id, storage_address_id, storage_value)) =
            rows.next().transpose()?
        {
            insert
                .execute(params![
                    block_number.get(),
                    contract_address_id,
                    storage_address_id,
                    storage_value
                ])
                .context("Inserting storage updates")?;
        }

        Ok(())
    }
}

mod indices {
    use super::*;

    pub(super) type CreateIndicesFn = fn(&rusqlite::Transaction<'_>) -> anyhow::Result<()>;

    pub(super) fn block_signatures(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
        tx.execute(
            "CREATE UNIQUE INDEX block_signatures_block_number ON block_signatures(block_number);",
            [],
        )
        .context("Creating block_signatures_block_number index")?;

        Ok(())
    }

    pub(super) fn class_definitions(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
        tx.execute(
            "CREATE INDEX class_definitions_block_number ON class_definitions(block_number);",
            [],
        )
        .context("Creating class_definitions_block_number index")?;

        Ok(())
    }

    pub(super) fn contract_updates(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
        tx.execute_batch(
            r"
            CREATE INDEX contract_updates_block_number 
                ON contract_updates(block_number);
            CREATE INDEX contract_updates_address_block_number 
                ON contract_updates(contract_address, block_number);
            ",
        )
        .context("Creating contract_updates_address_block_number index")?;

        Ok(())
    }

    pub(super) fn nonce_updates(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
        tx.execute_batch(
            r"
            CREATE INDEX nonce_updates_block_number 
                ON nonce_updates(block_number);
            CREATE INDEX nonce_updates_contract_address_id_block_number 
                ON nonce_updates(contract_address_id, block_number);
            ",
        )
        .context("Creating nonce_updates_contract_address_id_block_number index")?;

        Ok(())
    }

    pub(super) fn storage_updates(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
        tx.execute_batch(
            r"
            CREATE INDEX storage_updates_block_number 
                ON storage_updates(block_number);
            CREATE INDEX storage_updates_contract_address_id_storage_address_id_block_number 
                ON storage_updates(contract_address_id, storage_address_id, block_number);
            ",
        )
        .context("Creating storage_updates indices")?;

        Ok(())
    }
}
