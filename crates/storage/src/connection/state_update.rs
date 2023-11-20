use anyhow::Context;
use pathfinder_common::state_update::ContractClassUpdate;
use pathfinder_common::{
    BlockHash, BlockNumber, ClassHash, ContractAddress, ContractNonce, SierraHash, StateCommitment,
    StateUpdate, StorageAddress, StorageCommitment, StorageValue,
};

use crate::{prelude::*, BlockId};

/// Inserts a canonical [StateUpdate] into storage.
pub(super) fn insert_state_update(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    state_update: &StateUpdate,
) -> anyhow::Result<()> {
    let mut insert_nonce = tx
        .inner()
        .prepare_cached(
            "INSERT INTO nonce_updates (block_number, contract_address, nonce) VALUES (?, ?, ?)",
        )
        .context("Preparing nonce insert statement")?;

    let mut insert_storage = tx
        .inner().prepare_cached("INSERT INTO storage_updates (block_number, contract_address, storage_address, storage_value) VALUES (?, ?, ?, ?)")
        .context("Preparing nonce insert statement")?;

    let mut insert_contract = tx
        .inner().prepare_cached("INSERT INTO contract_updates (block_number, contract_address, class_hash) VALUES (?, ?, ?)")
        .context("Preparing contract insert statement")?;

    let mut update_class_defs = tx
        .inner()
        .prepare_cached(
            "UPDATE class_definitions SET block_number=? WHERE hash=? AND block_number IS NULL",
        )
        .context("Preparing class definition block number update statement")?;

    for (address, update) in &state_update.contract_updates {
        if let Some(class_update) = &update.class {
            insert_contract
                .execute(params![&block_number, address, &class_update.class_hash()])
                .context("Inserting deployed contract")?;
        }

        if let Some(nonce) = &update.nonce {
            insert_nonce
                .execute(params![&block_number, address, nonce])
                .context("Inserting nonce update")?;
        }

        for (key, value) in &update.storage {
            insert_storage
                .execute(params![&block_number, address, key, value])
                .context("Inserting storage update")?;
        }
    }

    for (address, update) in &state_update.system_contract_updates {
        for (key, value) in &update.storage {
            insert_storage
                .execute(params![&block_number, address, key, value])
                .context("Inserting system storage update")?;
        }
    }

    // Set all declared classes block numbers. Class definitions are inserted by a separate mechanism, prior
    // to state update inserts. However, since the class insertion does not know with which block number to
    // associate with the class definition, we need to fill it in here.
    let sierra = state_update
        .declared_sierra_classes
        .keys()
        .map(|sierra| ClassHash(sierra.0));
    let cairo = state_update.declared_cairo_classes.iter().copied();
    // Older cairo 0 classes were never declared, but instead got implicitly declared on first deployment.
    // Until such classes disappear we need to cater for them here. This works because the sql only
    // updates the row if it is null.
    let deployed = state_update
        .contract_updates
        .iter()
        .filter_map(|(_, update)| match update.class {
            Some(ContractClassUpdate::Deploy(x)) => Some(x),
            _ => None,
        });

    let declared_classes = sierra.chain(cairo).chain(deployed);

    for class in declared_classes {
        update_class_defs.execute(params![&block_number, &class])?;
    }

    Ok(())
}

fn block_details(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<(BlockNumber, BlockHash, StateCommitment, StateCommitment)>> {
    use const_format::formatcp;

    const PREFIX: &str = r"SELECT b1.number, b1.hash, b1.storage_commitment, b1.class_commitment, b2.storage_commitment, b2.class_commitment FROM block_headers b1 
            LEFT OUTER JOIN block_headers b2 ON b2.number = b1.number - 1";

    const LATEST: &str = formatcp!("{PREFIX} ORDER BY b1.number DESC LIMIT 1");
    const NUMBER: &str = formatcp!("{PREFIX} WHERE b1.number = ?");
    const HASH: &str = formatcp!("{PREFIX} WHERE b1.hash = ?");

    let handle_row = |row: &rusqlite::Row<'_>| {
        let number = row.get_block_number(0)?;
        let hash = row.get_block_hash(1)?;
        let storage_commitment = row.get_storage_commitment(2)?;
        let class_commitment = row.get_class_commitment(3)?;
        // The genesis block would not have a value.
        let parent_storage_commitment = row.get_optional_storage_commitment(4)?.unwrap_or_default();
        let parent_class_commitment = row.get_optional_class_commitment(5)?.unwrap_or_default();

        let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
        let parent_state_commitment = if parent_storage_commitment == StorageCommitment::ZERO {
            StateCommitment::ZERO
        } else {
            StateCommitment::calculate(parent_storage_commitment, parent_class_commitment)
        };

        Ok((number, hash, state_commitment, parent_state_commitment))
    };

    let tx = tx.inner();

    match block {
        BlockId::Latest => tx.query_row(LATEST, [], handle_row),
        BlockId::Number(number) => tx.query_row(NUMBER, params![&number], handle_row),
        BlockId::Hash(hash) => tx.query_row(HASH, params![&hash], handle_row),
    }
    .optional()
    .map_err(Into::into)
}

pub(super) fn state_update(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<StateUpdate>> {
    let Some((block_number, block_hash, state_commitment, parent_state_commitment)) =
        block_details(tx, block).context("Querying block header")?
    else {
        return Ok(None);
    };

    let mut state_update = StateUpdate::default()
        .with_block_hash(block_hash)
        .with_state_commitment(state_commitment)
        .with_parent_state_commitment(parent_state_commitment);

    let mut stmt = tx
        .inner()
        .prepare_cached("SELECT contract_address, nonce FROM nonce_updates WHERE block_number = ?")
        .context("Preparing nonce update query statement")?;

    let mut nonces = stmt
        .query_map(params![&block_number], |row| {
            let contract_address = row.get_contract_address(0)?;
            let nonce = row.get_contract_nonce(1)?;

            Ok((contract_address, nonce))
        })
        .context("Querying nonce updates")?;

    while let Some((address, nonce)) = nonces
        .next()
        .transpose()
        .context("Iterating over nonce query rows")?
    {
        state_update = state_update.with_contract_nonce(address, nonce);
    }

    let mut stmt = tx
        .inner().prepare_cached(
            "SELECT contract_address, storage_address, storage_value FROM storage_updates WHERE block_number = ?"
        )
        .context("Preparing storage update query statement")?;
    let mut storage_diffs = stmt
        .query_map(params![&block_number], |row| {
            let address: ContractAddress = row.get_contract_address(0)?;
            let key: StorageAddress = row.get_storage_address(1)?;
            let value: StorageValue = row.get_storage_value(2)?;

            Ok((address, key, value))
        })
        .context("Querying storage updates")?;

    while let Some((address, key, value)) = storage_diffs
        .next()
        .transpose()
        .context("Iterating over storage query rows")?
    {
        state_update = if address == ContractAddress::ONE {
            state_update.with_system_storage_update(address, key, value)
        } else {
            state_update.with_storage_update(address, key, value)
        };
    }

    let mut stmt = tx
        .inner()
        .prepare_cached(
            r"SELECT
                class_definitions.hash AS class_hash,
                casm_definitions.compiled_class_hash AS compiled_class_hash
            FROM
                class_definitions
            LEFT OUTER JOIN
                casm_definitions ON casm_definitions.hash = class_definitions.hash
            WHERE
                class_definitions.block_number = ?",
        )
        .context("Preparing class declaration query statement")?;

    let mut declared_classes = stmt
        .query_map(params![&block_number], |row| {
            let class_hash: ClassHash = row.get_class_hash(0)?;
            let casm_hash = row.get_optional_casm_hash(1)?;

            Ok((class_hash, casm_hash))
        })
        .context("Querying class declarations")?;

    while let Some((class_hash, casm)) = declared_classes
        .next()
        .transpose()
        .context("Iterating over class declaration query rows")?
    {
        state_update = match casm {
            Some(casm) => state_update.with_declared_sierra_class(SierraHash(class_hash.0), casm),
            None => state_update.with_declared_cairo_class(class_hash),
        };
    }

    let mut stmt = tx
        .inner().prepare_cached(
            r"SELECT
                cu1.contract_address AS contract_address,
                cu1.class_hash AS class_hash,
                cu2.block_number IS NOT NULL AS is_replaced
            FROM
                contract_updates cu1
            LEFT OUTER JOIN
                contract_updates cu2 ON cu1.contract_address = cu2.contract_address AND cu2.block_number < cu1.block_number
            WHERE
                cu1.block_number = ?",
        )
        .context("Preparing contract update query statement")?;

    let mut deployed_and_replaced_contracts = stmt
        .query_map(params![&block_number], |row| {
            let address: ContractAddress = row.get_contract_address(0)?;
            let class_hash: ClassHash = row.get_class_hash(1)?;
            let is_replaced: bool = row.get(2)?;

            Ok((address, class_hash, is_replaced))
        })
        .context("Querying contract deployments")?;

    while let Some((address, class_hash, is_replaced)) = deployed_and_replaced_contracts
        .next()
        .transpose()
        .context("Iterating over contract deployment query rows")?
    {
        state_update = if is_replaced {
            state_update.with_replaced_class(address, class_hash)
        } else {
            state_update.with_deployed_contract(address, class_hash)
        };
    }

    Ok(Some(state_update))
}

pub(super) fn storage_value(
    tx: &Transaction<'_>,
    block: BlockId,
    contract_address: ContractAddress,
    key: StorageAddress,
) -> anyhow::Result<Option<StorageValue>> {
    match block {
        BlockId::Latest => tx.inner().query_row(
            r"SELECT storage_value FROM storage_updates 
                WHERE contract_address = ? AND storage_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &key],
            |row| row.get_storage_value(0),
        ),
        BlockId::Number(number) => tx.inner().query_row(
            r"SELECT storage_value FROM storage_updates
                WHERE contract_address = ? AND storage_address = ? AND block_number <= ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &key, &number],
            |row| row.get_storage_value(0),
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            r"SELECT storage_value FROM storage_updates
                WHERE contract_address = ? AND storage_address = ? AND block_number <= (
                    SELECT number FROM canonical_blocks WHERE hash = ?
                )
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &key, &hash],
            |row| row.get_storage_value(0),
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
        BlockId::Number(number) => tx.inner().query_row(
            "SELECT EXISTS(SELECT 1 FROM contract_updates WHERE contract_address = ? AND block_number <= ?)",
            params![&contract_address, &number],
            |row| row.get(0),
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            r"SELECT EXISTS(
                SELECT 1 FROM contract_updates WHERE contract_address = ? AND block_number <= (
                    SELECT number FROM canonical_blocks WHERE hash = ?
                )
            )",
            params![&contract_address, &hash],
            |row| row.get(0),
        ),
        BlockId::Latest => tx.inner().query_row(
            "SELECT EXISTS(SELECT 1 FROM contract_updates WHERE contract_address = ?)",
            params![&contract_address],
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
        BlockId::Latest => tx.inner().query_row(
            r"SELECT nonce FROM nonce_updates
                WHERE contract_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address],
            |row| row.get_contract_nonce(0),
        ),
        BlockId::Number(number) => tx.inner().query_row(
            r"SELECT nonce FROM nonce_updates
                WHERE contract_address = ? AND block_number <= ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &number],
            |row| row.get_contract_nonce(0),
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            r"SELECT nonce FROM nonce_updates
                WHERE contract_address = ? AND block_number <= (
                    SELECT number FROM canonical_blocks WHERE hash = ?
                )
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &hash],
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
        BlockId::Latest => tx.inner().query_row(
            r"SELECT class_hash FROM contract_updates
                WHERE contract_address = ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address],
            |row| row.get_class_hash(0),
        ),
        BlockId::Number(number) => tx.inner().query_row(
            r"SELECT class_hash FROM contract_updates
                WHERE contract_address = ? AND block_number <= ?
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &number],
            |row| row.get_class_hash(0),
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            r"SELECT class_hash FROM contract_updates
                WHERE contract_address = ? AND block_number <= (
                    SELECT number FROM canonical_blocks WHERE hash = ?
                )
                ORDER BY block_number DESC LIMIT 1",
            params![&contract_address, &hash],
            |row| row.get_class_hash(0),
        ),
    }
    .optional()
    .map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::BlockHeader;

    use super::super::class::{casm_definition_at, casm_hash_at};
    use super::*;

    #[test]
    fn contract_class_hash() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        let original_class = class_hash!("0xdeadbeef");
        let replaced_class = class_hash!("0xdeadbeefabcdef");
        let definition = b"example definition";
        let contract = contract_address!("0x12345");

        let header_0 = BlockHeader::builder().finalize_with_hash(block_hash!("0xabc"));
        let header_1 = header_0
            .child_builder()
            .finalize_with_hash(block_hash!("0xabcdef"));
        let header_2 = header_1
            .child_builder()
            .finalize_with_hash(block_hash!("0xa111123"));
        let header_3 = header_2
            .child_builder()
            .finalize_with_hash(block_hash!("0xa111123aaa"));
        let header_4 = header_3
            .child_builder()
            .finalize_with_hash(block_hash!("0xa111123aaafff"));

        let diff_0 = StateUpdate::default();
        let diff_1 = StateUpdate::default()
            .with_declared_cairo_class(original_class)
            .with_deployed_contract(contract, original_class);
        let diff_2 = StateUpdate::default().with_replaced_class(contract, replaced_class);
        let diff_3 = StateUpdate::default();
        let diff_4 = StateUpdate::default();

        tx.insert_cairo_class(original_class, definition).unwrap();
        tx.insert_cairo_class(replaced_class, definition).unwrap();

        tx.insert_block_header(&header_0).unwrap();
        tx.insert_block_header(&header_1).unwrap();
        tx.insert_block_header(&header_2).unwrap();
        tx.insert_block_header(&header_3).unwrap();
        tx.insert_block_header(&header_4).unwrap();

        tx.insert_state_update(header_0.number, &diff_0).unwrap();
        tx.insert_state_update(header_1.number, &diff_1).unwrap();
        tx.insert_state_update(header_2.number, &diff_2).unwrap();
        tx.insert_state_update(header_3.number, &diff_3).unwrap();
        tx.insert_state_update(header_4.number, &diff_4).unwrap();

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

        let non_existent = contract_address!("0xaaaaa");
        let non_existent =
            super::contract_class_hash(&tx, BlockNumber::GENESIS.into(), non_existent).unwrap();
        assert_eq!(non_existent, None);

        // Query a few blocks after deployment as well. This is a regression case where querying by
        // block hash failed to find the class hash if it wasn't literally the deployed block.
        let is_replaced =
            super::contract_class_hash(&tx, header_4.number.into(), contract).unwrap();
        assert_eq!(is_replaced, Some(replaced_class));
        let is_replaced = super::contract_class_hash(&tx, header_4.hash.into(), contract).unwrap();
        assert_eq!(is_replaced, Some(replaced_class));
    }

    #[test]
    fn state_update() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        // Submit the class definitions since this occurs out of band of the header and state diff.
        let cairo_hash = class_hash_bytes!(b"cairo class hash");
        let sierra_hash = sierra_hash_bytes!(b"sierra hash");
        let casm_hash = casm_hash_bytes!(b"casm hash");

        let cairo_hash2 = class_hash_bytes!(b"cairo class hash again");

        tx.insert_cairo_class(cairo_hash, b"cairo definition")
            .unwrap();
        tx.insert_cairo_class(cairo_hash2, b"cairo definition 2")
            .unwrap();

        tx.insert_sierra_class(
            &sierra_hash,
            b"sierra definition",
            &casm_hash,
            b"casm definition",
            "compiler version",
        )
        .unwrap();

        // Create genesis block with a deployed contract so we can replace it in the
        // next block and test against it.
        let contract_address = contract_address_bytes!(b"contract addr");
        let genesis_state_update = StateUpdate::default()
            .with_declared_cairo_class(cairo_hash)
            .with_deployed_contract(contract_address, cairo_hash);
        let header = BlockHeader::builder().finalize_with_hash(block_hash!("0xabc"));
        tx.insert_block_header(&header).unwrap();
        tx.insert_state_update(header.number, &genesis_state_update)
            .unwrap();

        // The actual data we want to query.
        let header = header
            .child_builder()
            .finalize_with_hash(block_hash!("0xabcdef"));
        let state_update = StateUpdate::default()
            .with_block_hash(header.hash)
            .with_storage_update(
                contract_address,
                storage_address_bytes!(b"storage key"),
                storage_value_bytes!(b"storage value"),
            )
            .with_system_storage_update(
                ContractAddress::ONE,
                storage_address_bytes!(b"key"),
                storage_value_bytes!(b"value"),
            )
            .with_deployed_contract(
                contract_address_bytes!(b"contract addr 2"),
                ClassHash(sierra_hash.0),
            )
            .with_declared_cairo_class(cairo_hash2)
            .with_declared_sierra_class(sierra_hash, casm_hash)
            .with_contract_nonce(contract_address, contract_nonce_bytes!(b"nonce"))
            .with_replaced_class(contract_address, ClassHash(sierra_hash.0));

        tx.insert_block_header(&header).unwrap();
        tx.insert_state_update(header.number, &state_update)
            .unwrap();

        let result = super::state_update(&tx, header.number.into())
            .unwrap()
            .unwrap();
        assert_eq!(result, state_update);

        // check getters for compiled class
        let hash = casm_hash_at(&tx, BlockId::Latest, ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(hash, casm_hash);

        let definition = casm_definition_at(&tx, BlockId::Latest, ClassHash(sierra_hash.0))
            .unwrap()
            .unwrap();
        assert_eq!(definition, b"casm definition");

        // non-existent state update
        let non_existent = super::state_update(&tx, (header.number + 1).into()).unwrap();
        assert_eq!(non_existent, None);
    }

    mod contract_state {
        //! Tests involving contract nonces and storage.
        use super::*;

        /// Create and inserts a basic state diff for testing.
        fn setup() -> (crate::Connection, StateUpdate, BlockHeader) {
            let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
            let tx = db.transaction().unwrap();

            let header = BlockHeader::builder().finalize_with_hash(block_hash_bytes!(b"hash"));
            let contract_address = contract_address_bytes!(b"contract address");
            let contract_address2 = contract_address_bytes!(b"contract address 2");
            let state_update = StateUpdate::default()
                .with_contract_nonce(contract_address, contract_nonce_bytes!(b"nonce value"))
                .with_contract_nonce(contract_address2, contract_nonce_bytes!(b"nonce value 2"))
                .with_storage_update(
                    contract_address,
                    storage_address_bytes!(b"storage address"),
                    storage_value_bytes!(b"storage value"),
                );

            tx.insert_block_header(&header).unwrap();
            tx.insert_state_update(header.number, &state_update)
                .unwrap();
            tx.commit().unwrap();

            (db, state_update, header)
        }

        #[test]
        fn get_contract_nonce() {
            let (mut db, state_update, header) = setup();
            let tx = db.transaction().unwrap();

            // Valid 1st contract nonce
            let (contract, expected) = state_update
                .contract_updates
                .iter()
                .filter_map(|(addr, update)| update.nonce.map(|n| (*addr, n)))
                .next()
                .unwrap();

            let latest = contract_nonce(&tx, contract, BlockId::Latest)
                .unwrap()
                .unwrap();
            assert_eq!(latest, expected);

            let by_number = contract_nonce(&tx, contract, header.number.into())
                .unwrap()
                .unwrap();
            assert_eq!(by_number, expected);

            let by_hash = contract_nonce(&tx, contract, header.hash.into())
                .unwrap()
                .unwrap();
            assert_eq!(by_hash, expected);

            // Valid 2nd contract nonce. This exercises a bug where we didn't actually
            // use the contract address when querying by hash. Checking an additional
            // contract guards against only having a single entree to find.
            let (contract, expected) = state_update
                .contract_updates
                .iter()
                .filter_map(|(addr, update)| update.nonce.map(|n| (*addr, n)))
                .nth(1)
                .unwrap();

            let latest = contract_nonce(&tx, contract, BlockId::Latest)
                .unwrap()
                .unwrap();
            assert_eq!(latest, expected);

            let by_number = contract_nonce(&tx, contract, header.number.into())
                .unwrap()
                .unwrap();
            assert_eq!(by_number, expected);

            let by_hash = contract_nonce(&tx, contract, header.hash.into())
                .unwrap()
                .unwrap();
            assert_eq!(by_hash, expected);

            // Invalid i.e. missing contract should be None
            let invalid_contract = contract_address_bytes!(b"invalid");
            let invalid_latest = contract_nonce(&tx, invalid_contract, BlockId::Latest).unwrap();
            assert_eq!(invalid_latest, None);
            let invalid_by_hash =
                contract_nonce(&tx, invalid_contract, block_hash_bytes!(b"invalid").into())
                    .unwrap();
            assert_eq!(invalid_by_hash, None);
            let invalid_by_number =
                contract_nonce(&tx, invalid_contract, BlockNumber::MAX.into()).unwrap();
            assert_eq!(invalid_by_number, None);
        }

        #[test]
        fn get_storage_value() {
            let (mut db, state_update, header) = setup();
            let tx = db.transaction().unwrap();

            let (contract, key, expected) = state_update
                .contract_updates
                .iter()
                .flat_map(|(addr, update)| {
                    update
                        .storage
                        .iter()
                        .map(|(key, value)| (*addr, *key, *value))
                })
                .next()
                .unwrap();

            // Valid key and contract.
            let latest = storage_value(&tx, BlockId::Latest, contract, key)
                .unwrap()
                .unwrap();
            assert_eq!(latest, expected);
            let by_hash = storage_value(&tx, header.hash.into(), contract, key)
                .unwrap()
                .unwrap();
            assert_eq!(by_hash, expected);
            let by_number = storage_value(&tx, header.number.into(), contract, key)
                .unwrap()
                .unwrap();
            assert_eq!(by_number, expected);

            // Invalid key should be none
            let invalid_key = storage_address_bytes!(b"invalid key");
            let latest = storage_value(&tx, BlockId::Latest, contract, invalid_key).unwrap();
            assert_eq!(latest, None);
            let by_hash = storage_value(
                &tx,
                block_hash_bytes!(b"invalid").into(),
                contract,
                invalid_key,
            )
            .unwrap();
            assert_eq!(by_hash, None);
            let by_number =
                storage_value(&tx, BlockNumber::MAX.into(), contract, invalid_key).unwrap();
            assert_eq!(by_number, None);

            // Invalid contract should be none
            let invalid_contract = contract_address_bytes!(b"invalid");
            let latest = storage_value(&tx, BlockId::Latest, invalid_contract, key).unwrap();
            assert_eq!(latest, None);
            let by_hash = storage_value(&tx, header.hash.into(), invalid_contract, key).unwrap();
            assert_eq!(by_hash, None);
            let by_number =
                storage_value(&tx, header.number.into(), invalid_contract, key).unwrap();
            assert_eq!(by_number, None);
        }
    }
}
