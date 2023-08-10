use anyhow::Context;
use rusqlite::OptionalExtension;
use stark_hash::Felt;

/// This migration renames the starknet_blocks to block_headers and adds the state_commitment,
/// transaction_count and event_count columns, and also renames the root column to storage_commitment.
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    tracing::info!("Refactoring the block_headers table, this may take a while");

    tx.execute("ALTER TABLE starknet_blocks RENAME TO block_headers", [])
        .context("Renaming starknet_blocks table to block_headers")?;

    tx.execute(
        "ALTER TABLE block_headers RENAME COLUMN root TO storage_commitment",
        [],
    )
    .context("Renaming block_headers.root column to block_headers.storage_commitment")?;

    tx.execute(
        "ALTER TABLE block_headers ADD COLUMN state_commitment BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000'",
        [],
    )
    .context("Adding state_commitment column")?;

    tx.execute(
        "ALTER TABLE block_headers ADD COLUMN transaction_count INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .context("Adding transaction_count column")?;

    tx.execute(
        "ALTER TABLE block_headers ADD COLUMN event_count INTEGER NOT NULL DEFAULT 0",
        [],
    )
    .context("Adding event_count column")?;

    tx.execute(
        r"UPDATE block_headers SET transaction_count = (
            SELECT COUNT(1) FROM starknet_transactions WHERE starknet_transactions.block_hash = block_headers.hash
        )",
        [],
    )
    .context("Setting tx counts")?;

    tx.execute(
        r"UPDATE block_headers SET event_count = (
            SELECT COUNT(1) FROM starknet_events WHERE starknet_events.block_number = block_headers.number
        )",
        [],
    )
    .context("Setting event counts")?;

    tx.execute(
        r"UPDATE block_headers SET state_commitment = storage_commitment WHERE class_commitment IS NULL OR class_commitment = x'0000000000000000000000000000000000000000000000000000000000000000'",
        [],
    )
    .context("Setting state_commitment = storage_commitment")?;

    let Some(start): Option<i64> = tx
        .query_row(
            "SELECT number FROM block_headers WHERE state_commitment = x'0000000000000000000000000000000000000000000000000000000000000000' ORDER BY number ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .context("Counting rows")? else {
            return Ok(());
        };

    let mut reader = tx
        .prepare(
            "SELECT number, storage_commitment, class_commitment FROM block_headers WHERE number >= ?",
        )
        .context("Preparing commitment reader statement")?;
    let mut writer = tx
        .prepare("UPDATE block_headers SET state_commitment = ? WHERE number = ?")
        .context("Preparing commitment writer statement")?;

    let rows = reader
        .query_map([start], |row| {
            let number: u64 = row.get(0).unwrap();
            let storage: Vec<u8> = row.get(1).unwrap();
            let class: Vec<u8> = row.get(2).unwrap();

            Ok((number, storage, class))
        })
        .context("Querying commitments")?;

    const GLOBAL_STATE_VERSION: Felt = pathfinder_common::felt_bytes!(b"STARKNET_STATE_V0");
    for row in rows {
        let (number, storage, class) = row.context("Iterating over rows")?;

        let storage = Felt::from_be_slice(&storage).context("Parsing storage commitment bytes")?;
        let class = Felt::from_be_slice(&class).context("Parsing class commitment bytes")?;

        let state_commitment: Felt = stark_poseidon::poseidon_hash_many(&[
            GLOBAL_STATE_VERSION.into(),
            storage.into(),
            class.into(),
        ])
        .into();

        writer
            .execute(rusqlite::params![number, state_commitment.as_be_bytes()])
            .context("Updating state commitment")?;
    }

    Ok(())
}
