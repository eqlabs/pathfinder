use anyhow::Context;

/// Adds support for tracking class declarations i.e. at which block they were declared.
///
/// More specifically, this migration:
/// - adds the `contract_code.declared_on` column
/// - adds a unique index to `canonical_blocks.hash` to let it be used as a FK
/// - backfills `contract_code.declared_on` for existing classes
pub(crate) fn migrate(tx: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    // We didn't declare canonical_blocks.hash as unique, so we cannot use it as a
    // foreign key. To fix this, we create a unique index on it.
    tx.execute(
        "CREATE UNIQUE INDEX canonical_block_hash_idx ON canonical_blocks(hash); ",
        [],
    )
    .context("Creating unique index for canonical_blocks(hash)")?;

    // Add the new column to `contract_code` table
    tx.execute(
        r"ALTER TABLE contract_code ADD COLUMN declared_on BLOB 
        DEFAULT NULL 
        REFERENCES canonical_blocks(hash) ON DELETE SET NULL",
        [],
    )
    .context("Adding `declared_on` column to `contract_code` table")?;

    // Backfill existing classes using the deployed and declared classes in state updates.
    //
    // Ordering is important as a contract deployment can also act as a class declaration if the
    // class was undeclared at that point.
    let mut stmt = tx
        .prepare(
            r"SELECT data FROM starknet_state_updates 
            JOIN starknet_blocks WHERE starknet_state_updates.block_hash=starknet_blocks.hash
            ORDER BY number",
        )
        .context("Preparing statement for reading state updates")?;

    let mut classes = std::collections::HashMap::new();
    let mut rows = stmt.query([]).context("Executing query")?;
    while let Some(row) = rows.next()? {
        let state_update = row.get_ref_unwrap(0).as_blob()?;
        let state_update = zstd::decode_all(state_update).context("Decompressing state update")?;
        let state_update: types::StateUpdate =
            serde_json::from_slice(&state_update).context("Deserializing state update")?;

        // We need to consider declared classes as well as deployed contracts.
        // The latter is required because originally starknet had deploy == declare & deploy.
        //
        // Note that in addition, StarkNet does not disallow declaring already declared classes.
        let declared = state_update
            .state_diff
            .declared_contracts
            .iter()
            .map(|c| c.class_hash);
        let deployed = state_update
            .state_diff
            .deployed_contracts
            .iter()
            .map(|c| c.class_hash);

        for c in declared.chain(deployed) {
            classes.entry(c).or_insert(state_update.block_hash);
        }
    }

    let mut stmt = tx
        .prepare("UPDATE contract_code SET declared_on=? WHERE hash=?")
        .context("Preparing update statement")?;
    for c in classes {
        let rows_changed = stmt
            .execute(rusqlite::params![c.1, c.0])
            .with_context(|| format!("Updating class {:?} at block {:?}", c.1, c.0))?;
        assert_eq!(rows_changed, 1);
    }

    Ok(())
}

/// Partial-copy of types required for deserialisation, this lets us change the original types without breaking this migration.
///
/// Only the paths that are actually requried are kept for deserialisation.
mod types {
    use pathfinder_common::{ClassHash, StarknetBlockHash};
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct StateUpdate {
        pub block_hash: StarknetBlockHash,
        pub state_diff: StateDiff,
    }

    #[derive(Deserialize)]
    pub struct StateDiff {
        pub declared_contracts: Vec<DeclaredContract>,
        pub deployed_contracts: Vec<DeployedContract>,
    }

    /// L2 state diff declared contract item.
    #[derive(Deserialize, Debug)]
    pub struct DeclaredContract {
        pub class_hash: ClassHash,
    }

    #[derive(Deserialize)]
    pub struct DeployedContract {
        pub class_hash: ClassHash,
    }
}
