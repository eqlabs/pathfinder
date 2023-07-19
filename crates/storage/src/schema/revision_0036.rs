use anyhow::Context;
use pathfinder_common::{ContractAddress, StorageValue};
use stark_hash::Felt;

use crate::params::{params, RowExt};

/// This migration adds the system contract updates which were mistakenly never inserted.
///
/// Thankfully we can avoid looking these values up in the state trie as the values can
/// be entirely determined from past blocks.
///
/// Each block, the system contract at 0x1 gets a new storage item referencing the block number
/// and hash from 10 blocks in the past.
///     key   = block number
///     value = block hash
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    let mut select = tx
        .prepare_cached(
            r"SELECT current.number, past.number, past.hash FROM starknet_blocks current
    JOIN starknet_versions ON current.version_id = starknet_versions.id 
    JOIN starknet_blocks past ON current.number - 10 = past.number
    WHERE starknet_versions.version = '0.12.0'",
        )
        .context("Preparing select statement")?;

    let rows = select.query_map([], |row| {
        let current = row.get_block_number(0)?;
        let past = row.get_block_number(1)?;
        let hash = row.get_block_hash(2)?;

        Ok((current, past, hash))
    })?;

    let mut insert = tx.prepare_cached(
        "INSERT INTO storage_updates (block_number, contract_address, storage_address, storage_value) VALUES (?, ?, ?, ?)"
    )
    .context("Preparing insert statement")?;

    for result in rows {
        let (current, past, hash) = result?;

        let past = StorageValue(Felt::from(past.get()));

        insert
            .execute(params![&current, &ContractAddress::ONE, &past, &hash])
            .context("Inserting storage update")?;
    }

    Ok(())
}
