use anyhow::Context;
use pathfinder_common::BlockNumber;

use crate::prelude::*;

use crate::types::state_update::{DeployedContract, Nonce, ReplacedClass, StateDiff, StorageDiff};

/// Inserts a canonical [StateDiff] into storage.
pub(super) fn insert_canonical_state_diff(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    state_diff: &StateDiff,
) -> anyhow::Result<()> {
    let mut insert_nonce = tx
        .prepare_cached(
            "INSERT INTO nonce_updates (block_number, contract_address, nonce) VALUES (?, ?, ?)",
        )
        .context("Preparing nonce insert statement")?;

    let mut insert_storage = tx
        .prepare_cached("INSERT INTO storage_updates (block_number, contract_address, storage_address, storage_value) VALUES (?, ?, ?, ?)")
        .context("Preparing nonce insert statement")?;

    let mut insert_contract = tx
        .prepare_cached("INSERT INTO contract_updates (block_number, contract_address, class_hash) VALUES (?, ?, ?)")
        .context("Preparing contract insert statement")?;

    let mut update_class_defs = tx
        .prepare_cached(
            "UPDATE class_definitions SET block_number=? WHERE hash=? AND block_number IS NULL",
        )
        .context("Preparing class definition block number update statement")?;

    // Insert contract deployments. Doing this first ensures that subsequent sections will be
    // guaranteed to have the contract address already interned (saving one insert).
    for DeployedContract {
        address,
        class_hash,
    } in &state_diff.deployed_contracts
    {
        insert_contract
            .execute(params![&block_number, address, class_hash])
            .context("Inserting deployed contract")?;
    }

    // Insert replaced class hashes
    for ReplacedClass {
        address,
        class_hash,
    } in &state_diff.replaced_classes
    {
        insert_contract
            .execute(params![&block_number, address, class_hash])
            .context("Inserting replaced class")?;
    }

    // Insert nonce updates
    for Nonce {
        contract_address,
        nonce,
    } in &state_diff.nonces
    {
        insert_nonce
            .execute(params![&block_number, contract_address, nonce])
            .context("Inserting nonce update")?;
    }

    // Insert storage updates
    for StorageDiff {
        address,
        key,
        value,
    } in &state_diff.storage_diffs
    {
        insert_storage
            .execute(params![&block_number, address, key, value])
            .context("Inserting storage update")?;
    }

    // Set all declared classes block numbers. Class definitions are inserted by a separate mechanism, prior
    // to state update inserts. However, since the class insertion does not know with which block number to
    // associate with the class definition, we need to fill it in here.
    let declared_classes = state_diff
        .declared_sierra_classes
        .iter()
        .map(|d| d.class_hash.0)
        .chain(state_diff.declared_contracts.iter().map(|d| d.class_hash.0))
        // Some old state updates did not have declared contracts, but instead any deployed contract could
        // be a new class declaration + deployment.
        .chain(state_diff.deployed_contracts.iter().map(|d| d.class_hash.0))
        .map(pathfinder_common::ClassHash);

    for class in declared_classes {
        update_class_defs.execute(params![&block_number, &class])?;
    }

    Ok(())
}
