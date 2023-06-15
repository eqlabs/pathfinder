use anyhow::Context;
use pathfinder_common::{
    BlockNumber, ClassHash, ContractAddress, ContractNonce, SierraHash, StorageAddress,
    StorageValue,
};

use crate::{prelude::*, BlockId};

use crate::types::state_update::{
    DeclaredCairoClass, DeclaredSierraClass, DeployedContract, Nonce, ReplacedClass, StateDiff,
    StorageDiff,
};

/// Inserts a canonical [StateDiff] into storage.
pub(super) fn insert_canonical_state_diff(
    tx: &Transaction<'_>,
    block_number: BlockNumber,
    state_diff: &StateDiff,
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

pub(super) fn state_diff(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<StateDiff>> {
    // Simplify the following queries by only relying on block number and not hash etc as well.
    let block_number = tx.block_id(block).context("Querying block number")?;
    let Some((block_number, _)) = block_number else {
        return Ok(None);
    };

    let mut stmt = tx
        .inner()
        .prepare_cached("SELECT contract_address, nonce FROM nonce_updates WHERE block_number = ?")
        .context("Preparing nonce update query statement")?;

    let nonces = stmt
        .query_map(params![&block_number], |row| {
            let contract_address = row.get_contract_address(0)?;
            let nonce = row.get_contract_nonce(1)?;

            Ok(Nonce {
                contract_address,
                nonce,
            })
        })
        .context("Querying nonce updates")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over nonce query rows")?;

    let mut stmt = tx
        .inner().prepare_cached(
            "SELECT contract_address, storage_address, storage_value FROM storage_updates WHERE block_number = ?"
        )
        .context("Preparing storage update query statement")?;
    let storage_diffs = stmt
        .query_map(params![&block_number], |row| {
            let address: ContractAddress = row.get_contract_address(0)?;
            let key: StorageAddress = row.get_storage_address(1)?;
            let value: StorageValue = row.get_storage_value(2)?;

            Ok(StorageDiff {
                address,
                key,
                value,
            })
        })
        .context("Querying storage updates")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over storage query rows")?;

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

    let declared_classes = stmt
        .query_map(params![&block_number], |row| {
            let class_hash: ClassHash = row.get_class_hash(0)?;
            let casm_hash = row.get_optional_casm_hash(1)?;

            Ok((class_hash, casm_hash))
        })
        .context("Querying class declarations")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over class declaration query rows")?;

    let declared_sierra_classes = declared_classes
        .iter()
        .filter_map(|(sierra_hash, casm_hash)| {
            casm_hash.map(|casm| DeclaredSierraClass {
                class_hash: SierraHash(sierra_hash.0),
                compiled_class_hash: casm,
            })
        })
        .collect();

    let declared_contracts = declared_classes
        .into_iter()
        .filter_map(|(class_hash, casm_hash)| {
            casm_hash
                .is_none()
                .then_some(DeclaredCairoClass { class_hash })
        })
        .collect();

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

    let deployed_and_replaced_contracts = stmt
        .query_map(params![&block_number], |row| {
            let address: ContractAddress = row.get_contract_address(0)?;
            let class_hash: ClassHash = row.get_class_hash(1)?;
            let is_replaced: bool = row.get(2)?;

            Ok((address, class_hash, is_replaced))
        })
        .context("Querying contract deployments")?
        .collect::<Result<Vec<_>, _>>()
        .context("Iterating over contract deployment query rows")?;

    let replaced_classes = deployed_and_replaced_contracts
        .iter()
        .filter_map(|(address, class_hash, is_replaced)| {
            is_replaced.then_some(ReplacedClass {
                address: *address,
                class_hash: *class_hash,
            })
        })
        .collect();

    let deployed_contracts = deployed_and_replaced_contracts
        .iter()
        .filter_map(|(address, class_hash, is_replaced)| {
            (!is_replaced).then_some(DeployedContract {
                address: *address,
                class_hash: *class_hash,
            })
        })
        .collect();

    let diff = StateDiff {
        storage_diffs,
        declared_contracts,
        deployed_contracts,
        nonces,
        declared_sierra_classes,
        replaced_classes,
    };

    Ok(Some(diff))
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
    use pathfinder_common::{felt, felt_bytes, BlockHash, BlockHeader, CasmHash};

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

    #[test]
    fn state_diff() {
        let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
        let tx = db.transaction().unwrap();

        // Submit the class definitions since this occurs out of band of the header and state diff.
        let cairo_hash = ClassHash(felt_bytes!(b"cairo class hash"));
        let sierra_hash = SierraHash(felt_bytes!(b"sierra hash"));
        let casm_hash = CasmHash(felt_bytes!(b"casm hash"));

        let cairo_hash2 = ClassHash(felt_bytes!(b"cairo class hash again"));

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
        let contract_address = ContractAddress::new_or_panic(felt_bytes!(b"contract addr"));
        let genesis_diff = StateDiff::default()
            .add_declared_cairo_class(cairo_hash)
            .add_deployed_contract(contract_address, cairo_hash);
        let header = BlockHeader::builder().finalize_with_hash(BlockHash(felt!("0xabc")));
        tx.insert_block_header(&header).unwrap();
        tx.insert_state_diff(header.number, &genesis_diff).unwrap();

        // The actual data we want to query.
        // Note: create without builder to ensure we cover all the fields (and add new ones) in this test.
        let diff = StateDiff {
            storage_diffs: vec![StorageDiff {
                address: contract_address,
                key: StorageAddress::new_or_panic(felt_bytes!(b"storage key")),
                value: StorageValue(felt_bytes!(b"storage value")),
            }],
            declared_contracts: vec![DeclaredCairoClass {
                class_hash: cairo_hash2,
            }],
            deployed_contracts: vec![DeployedContract {
                address: ContractAddress::new_or_panic(felt_bytes!(b"contract addr 2")),
                class_hash: ClassHash(sierra_hash.0),
            }],
            nonces: vec![Nonce {
                contract_address,
                nonce: ContractNonce(felt_bytes!(b"nonce")),
            }],
            declared_sierra_classes: vec![DeclaredSierraClass {
                class_hash: SierraHash(felt_bytes!(b"sierra hash")),
                compiled_class_hash: CasmHash(felt_bytes!(b"casm hash")),
            }],
            replaced_classes: vec![
                // Replace the contract from the previous block.
                ReplacedClass {
                    address: contract_address,
                    class_hash: ClassHash(sierra_hash.0),
                },
            ],
        };

        let header = header
            .child_builder()
            .finalize_with_hash(BlockHash(felt!("0xabcdef")));
        tx.insert_block_header(&header).unwrap();
        tx.insert_state_diff(header.number, &diff).unwrap();

        let result = super::state_diff(&tx, header.number.into())
            .unwrap()
            .unwrap();
        assert_eq!(result, diff);

        let non_existent = super::state_diff(&tx, (header.number + 1).into()).unwrap();
        assert_eq!(non_existent, None);
    }

    mod contract_state {
        //! Tests involving contract nonces and storage.
        use super::*;

        /// Create and inserts a basic state diff for testing.
        fn setup() -> (crate::Connection, StateDiff, BlockHeader) {
            let mut db = crate::Storage::in_memory().unwrap().connection().unwrap();
            let tx = db.transaction().unwrap();

            let header = BlockHeader::builder().finalize_with_hash(BlockHash(felt_bytes!(b"hash")));
            let contract_adress = ContractAddress::new_or_panic(felt_bytes!(b"contract address"));
            let diff = StateDiff::default()
                .add_nonce_update(contract_adress, ContractNonce(felt_bytes!(b"nonce value")))
                .add_storage_update(
                    contract_adress,
                    StorageAddress::new_or_panic(felt_bytes!(b"storage address")),
                    StorageValue(felt_bytes!(b"storage value")),
                );

            tx.insert_block_header(&header).unwrap();
            tx.insert_state_diff(header.number, &diff).unwrap();
            tx.commit().unwrap();

            (db, diff, header)
        }

        #[test]
        fn get_contract_nonce() {
            let (mut db, diff, header) = setup();
            let tx = db.transaction().unwrap();

            // Valid contract nonce
            let (contract, expected) = diff
                .nonces
                .first()
                .map(|x| (x.contract_address, x.nonce))
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
            let invalid_contract = ContractAddress::new_or_panic(felt_bytes!(b"invalid"));
            let invalid_latest = contract_nonce(&tx, invalid_contract, BlockId::Latest).unwrap();
            assert_eq!(invalid_latest, None);
            let invalid_by_hash = contract_nonce(
                &tx,
                invalid_contract,
                BlockHash(felt_bytes!(b"invalid")).into(),
            )
            .unwrap();
            assert_eq!(invalid_by_hash, None);
            let invalid_by_number =
                contract_nonce(&tx, invalid_contract, BlockNumber::MAX.into()).unwrap();
            assert_eq!(invalid_by_number, None);
        }

        #[test]
        fn get_storage_value() {
            let (mut db, diff, header) = setup();
            let tx = db.transaction().unwrap();

            let (contract, key, expected) = diff
                .storage_diffs
                .first()
                .map(|x| (x.address, x.key, x.value))
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
            let invalid_key = StorageAddress::new_or_panic(felt_bytes!(b"invalid key"));
            let latest = storage_value(&tx, BlockId::Latest, contract, invalid_key).unwrap();
            assert_eq!(latest, None);
            let by_hash = storage_value(
                &tx,
                BlockHash(felt_bytes!(b"invalid")).into(),
                contract,
                invalid_key,
            )
            .unwrap();
            assert_eq!(by_hash, None);
            let by_number =
                storage_value(&tx, BlockNumber::MAX.into(), contract, invalid_key).unwrap();
            assert_eq!(by_number, None);

            // Invalid contract should be none
            let invalid_contract = ContractAddress::new_or_panic(felt_bytes!(b"invalid"));
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
