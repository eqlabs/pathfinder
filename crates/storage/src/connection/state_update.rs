use anyhow::Context;
use pathfinder_common::{
    BlockNumber, ClassHash, ContractAddress, ContractNonce, StorageAddress, StorageValue,
};

use crate::{prelude::*, BlockId};

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

pub(super) fn storage_value(
    tx: &Transaction<'_>,
    block: BlockId,
    contract_address: ContractAddress,
    key: StorageAddress,
) -> anyhow::Result<Option<StorageValue>> {
    match block {
        BlockId::Latest => tx.query_row(
            r"SELECT storage_value FROM storage_updates 
                WHERE contract_address = ? AND storage_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &key],
            |row| row.get_storage_value(0),
        ),
        BlockId::Number(number) => tx.query_row(
            r"SELECT storage_value FROM storage_updates
                WHERE contract_address = ? AND storage_address = ? AND block_number <= ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &key, &number],
            |row| row.get(0),
        ),
        BlockId::Hash(hash) => tx.query_row(
            r"SELECT storage_value FROM storage_updates
                WHERE contract_address = ? AND storage_address = ? AND block_number <= (
                    SELECT number FROM canonical_blocks WHERE hash = ?
                )
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &key, &hash],
            |row| row.get(0),
        ),
    }
    .optional()
    .map_err(|e| e.into())
}

pub(super) fn contract_exists(
    tx: &Transaction<'_>,
    contract_address: ContractAddress,
    block_id: BlockId,
) -> anyhow::Result<bool> {
    match block_id {
        BlockId::Number(number) => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM contract_updates WHERE contract_address = ? AND block_number <= ?)",
            params![&contract_address, &number],
            |row| row.get(0),
        ),
        BlockId::Hash(hash) => tx.query_row(
            r"SELECT EXISTS(
                SELECT 1 FROM contract_updates WHERE contract_address = ? AND block_number <= (
                    SELECT number FROM canonical_blocks WHERE hash = ?
                )
            )",
            params![&contract_address, &hash],
            |row| row.get(0),
        ),
        BlockId::Latest => tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM contract_updates WHERE contract_address = ?)",
            [contract_address],
            |row| row.get(0),
        ),
    }
    .context("Querying that contract exists")
}

pub(super) fn contract_nonce(
    tx: &Transaction<'_>,
    contract_address: ContractAddress,
    block_id: BlockId,
) -> anyhow::Result<Option<ContractNonce>> {
    match block_id {
        BlockId::Latest => tx.query_row(
            r"SELECT nonce FROM nonce_updates
                WHERE contract_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address],
            |row| row.get_contract_nonce(0),
        ),
        BlockId::Number(number) => tx.query_row(
            r"SELECT nonce FROM nonce_updates
                WHERE contract_address = ? AND block_number <= ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &number],
            |row| row.get_contract_nonce(0),
        ),
        BlockId::Hash(hash) => tx.query_row(
            r"SELECT nonce FROM nonce_updates
                JOIN canonical_blocks ON canonical_blocks.number = nonce_updates.block_number
                WHERE canonical_blocks.hash = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&hash],
            |row| row.get_contract_nonce(0),
        ),
    }
    .optional()
    .map_err(|e| e.into())
}

pub(super) fn contract_class_hash(
    tx: &Transaction<'_>,
    block_id: BlockId,
    contract_address: ContractAddress,
) -> anyhow::Result<Option<ClassHash>> {
    match block_id {
        BlockId::Latest => tx.query_row(
            r"SELECT class_hash FROM contract_updates
                WHERE contract_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address],
            |row| row.get_class_hash(0),
        ),
        BlockId::Number(number) => tx.query_row(
            r"SELECT class_hash FROM contract_updates
                WHERE contract_address = ? AND block_number <= ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &number],
            |row| row.get_class_hash(0),
        ),
        BlockId::Hash(hash) => tx.query_row(
            r"SELECT class_hash FROM contract_updates
                JOIN canonical_blocks ON canonical_blocks.number = contract_updates.block_number
                WHERE 
                    canonical_blocks.hash = ? AND 
                    block_number <= contract_updates.block_number AND 
                    contract_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&hash, &contract_address],
            |row| row.get_class_hash(0),
        ),
    }
    .optional()
    .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use pathfinder_common::{felt, BlockHash, BlockHeader};

    use super::*;

    #[test]
    fn contract_class_hash() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let original_class = ClassHash(felt!("0xdeadbeef"));
        let replaced_class = ClassHash(felt!("0xdeadbeefabcdef"));
        let definition = b"example definition";
        let contract = ContractAddress::new_or_panic(felt!("0x12345"));

        let header_0 = BlockHeader::builder().finalize_with_hash(BlockHash(felt!("0xabc")));
        let header_1 = header_0
            .child_builder()
            .finalize_with_hash(BlockHash(felt!("0xabcdef")));
        let header_2 = header_1
            .child_builder()
            .finalize_with_hash(BlockHash(felt!("0xa111123")));

        let diff_0 = StateDiff::default();
        let diff_1 = StateDiff::default()
            .add_declared_cairo_class(original_class)
            .add_deployed_contract(contract, original_class);
        let diff_2 = StateDiff::default().add_replaced_class(contract, replaced_class);

        tx.insert_cairo_class(original_class, definition).unwrap();
        tx.insert_cairo_class(replaced_class, definition).unwrap();

        tx.insert_block_header(&header_0).unwrap();
        tx.insert_block_header(&header_1).unwrap();
        tx.insert_block_header(&header_2).unwrap();

        tx.insert_state_diff(header_0.number, &diff_0).unwrap();
        tx.insert_state_diff(header_1.number, &diff_1).unwrap();
        tx.insert_state_diff(header_2.number, &diff_2).unwrap();

        let not_deployed_yet =
            super::contract_class_hash(&tx, header_0.number.into(), contract).unwrap();
        assert_eq!(not_deployed_yet, None);

        let not_deployed_yet =
            super::contract_class_hash(&tx, header_0.hash.into(), contract).unwrap();
        assert_eq!(not_deployed_yet, None);

        let is_deployed =
            super::contract_class_hash(&tx, header_1.number.into(), contract).unwrap();
        assert_eq!(is_deployed, Some(original_class));

        let is_deployed = super::contract_class_hash(&tx, header_1.hash.into(), contract).unwrap();
        assert_eq!(is_deployed, Some(original_class));

        let is_replaced =
            super::contract_class_hash(&tx, header_2.number.into(), contract).unwrap();
        assert_eq!(is_replaced, Some(replaced_class));

        let is_replaced = super::contract_class_hash(&tx, header_2.hash.into(), contract).unwrap();
        assert_eq!(is_replaced, Some(replaced_class));

        let non_existent = ContractAddress::new_or_panic(felt!("0xaaaaa"));
        let non_existent =
            super::contract_class_hash(&tx, BlockNumber::GENESIS.into(), non_existent).unwrap();
        assert_eq!(non_existent, None);
    }
}
