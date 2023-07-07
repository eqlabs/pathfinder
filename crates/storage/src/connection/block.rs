use anyhow::Context;
use pathfinder_common::{BlockHash, BlockHeader, BlockNumber, StarknetVersion, StateCommitment};

use crate::{prelude::*, BlockId};

pub(super) fn insert_block_header(
    tx: &Transaction<'_>,
    header: &BlockHeader,
) -> anyhow::Result<()> {
    // Intern the starknet version
    let version_id = intern_starknet_version(tx, &header.starknet_version)
        .context("Interning starknet version")?;

    // Insert the header
    tx.inner().execute(
        r"INSERT INTO starknet_blocks 
                   ( number,  hash,  root,  timestamp,  gas_price,  sequencer_address,  version_id,  transaction_commitment,  event_commitment,  class_commitment)
            VALUES (:number, :hash, :root, :timestamp, :gas_price, :sequencer_address, :version_id, :transaction_commitment, :event_commitment, :class_commitment)",
        named_params! {
            ":number": &header.number,
            ":hash": &header.hash,
            ":root": &header.storage_commitment,
            ":timestamp": &header.timestamp,
            ":gas_price": &header.gas_price.to_be_bytes().as_slice(),
            ":sequencer_address": &header.sequencer_address,
            ":version_id": &version_id,
            ":transaction_commitment": &header.transaction_commitment,
            ":event_commitment": &header.event_commitment,
            ":class_commitment": &header.class_commitment,
        },
    ).context("Inserting block header")?;

    // This must occur after the header is inserted as this table references the header table.
    tx.inner()
        .execute(
            "INSERT INTO canonical_blocks(number, hash) values(?,?)",
            params![&header.number, &header.hash],
        )
        .context("Inserting into canonical_blocks table")?;

    Ok(())
}

fn intern_starknet_version(tx: &Transaction<'_>, version: &StarknetVersion) -> anyhow::Result<i64> {
    let id: Option<i64> = tx
        .inner()
        .query_row(
            "SELECT id FROM starknet_versions WHERE version = ?",
            params![version],
            |r| Ok(r.get_unwrap(0)),
        )
        .optional()
        .context("Querying for an existing starknet_version")?;

    let id = if let Some(id) = id {
        id
    } else {
        // sqlite "autoincrement" for integer primary keys works like this: we leave it out of
        // the insert, even though it's not null, it will get max(id)+1 assigned, which we can
        // read back with last_insert_rowid
        let rows = tx
            .inner()
            .execute(
                "INSERT INTO starknet_versions(version) VALUES (?)",
                params![version],
            )
            .context("Inserting unique starknet_version")?;

        anyhow::ensure!(rows == 1, "Unexpected number of rows inserted: {rows}");

        tx.inner().last_insert_rowid()
    };

    Ok(id)
}

pub(super) fn purge_block(tx: &Transaction<'_>, block: BlockNumber) -> anyhow::Result<()> {
    // This table does not have an ON DELETE clause, so we do it manually.
    // TODO: migration to add ON DELETE.
    tx.inner()
        .execute(
            "UPDATE class_definitions SET block_number = NULL WHERE block_number = ?",
            params![&block],
        )
        .context("Unsetting class definitions block number")?;

    tx.inner()
        .execute(
            r"DELETE FROM starknet_transactions WHERE block_hash = (
                SELECT hash FROM canonical_blocks WHERE number = ?
            )",
            params![&block],
        )
        .context("Deleting transactions")?;

    tx.inner()
        .execute(
            "DELETE FROM canonical_blocks WHERE number = ?",
            params![&block],
        )
        .context("Deleting block from canonical_blocks table")?;

    tx.inner()
        .execute(
            "DELETE FROM starknet_blocks WHERE number = ?",
            params![&block],
        )
        .context("Deleting block from starknet_blocks table")?;

    Ok(())
}

pub(super) fn block_id(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<(BlockNumber, BlockHash)>> {
    match block {
        BlockId::Latest => tx.inner().query_row(
            "SELECT number, hash FROM canonical_blocks ORDER BY number DESC LIMIT 1",
            [],
            |row| {
                let number = row.get_block_number(0)?;
                let hash = row.get_block_hash(1)?;

                Ok((number, hash))
            },
        ),
        BlockId::Number(number) => tx.inner().query_row(
            "SELECT hash FROM canonical_blocks WHERE number = ?",
            params![&number],
            |row| {
                let hash = row.get_block_hash(0)?;
                Ok((number, hash))
            },
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            "SELECT number FROM canonical_blocks WHERE hash = ?",
            params![&hash],
            |row| {
                let number = row.get_block_number(0)?;
                Ok((number, hash))
            },
        ),
    }
    .optional()
    .map_err(|e| e.into())
}

pub(super) fn block_exists(tx: &Transaction<'_>, block: BlockId) -> anyhow::Result<bool> {
    match block {
        BlockId::Latest => {
            tx.inner()
                .query_row("SELECT EXISTS(SELECT 1 FROM canonical_blocks)", [], |row| {
                    row.get(0)
                })
        }
        BlockId::Number(number) => tx.inner().query_row(
            "SELECT EXISTS(SELECT 1 FROM canonical_blocks WHERE number = ?)",
            params![&number],
            |row| row.get(0),
        ),
        BlockId::Hash(hash) => tx.inner().query_row(
            "SELECT EXISTS(SELECT 1 FROM canonical_blocks WHERE hash = ?)",
            params![&hash],
            |row| row.get(0),
        ),
    }
    .map_err(|e| e.into())
}

pub(super) fn block_header(
    tx: &Transaction<'_>,
    block: BlockId,
) -> anyhow::Result<Option<BlockHeader>> {
    // TODO: is LEFT JOIN reasonable? It's required because version ID can be null for non-existent versions.
    const BASE_SQL: &str = "SELECT * FROM starknet_blocks LEFT JOIN starknet_versions ON starknet_blocks.version_id = starknet_versions.id";
    let sql = match block {
        BlockId::Latest => format!("{BASE_SQL} ORDER BY number DESC LIMIT 1"),
        BlockId::Number(_) => format!("{BASE_SQL} WHERE number = ?"),
        BlockId::Hash(_) => format!("{BASE_SQL} WHERE hash = ?"),
    };

    let parse_row = |row: &rusqlite::Row<'_>| {
        let number = row.get_block_number("number")?;
        let hash = row.get_block_hash("hash")?;
        let storage_commitment = row.get_storage_commitment("root")?;
        let timestamp = row.get_timestamp("timestamp")?;
        let gas_price = row.get_gas_price("gas_price")?;
        let sequencer_address = row.get_sequencer_address("sequencer_address")?;
        let transaction_commitment = row.get_transaction_commitment("transaction_commitment")?;
        let event_commitment = row.get_event_commitment("event_commitment")?;
        let class_commitment = row.get_class_commitment("class_commitment")?;
        let starknet_version = row.get_starknet_version("version")?;

        // TODO: this really needs to get stored instead.
        let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
        // TODO: test what happens when a field is null.

        let header = BlockHeader {
            hash,
            number,
            timestamp,
            gas_price,
            sequencer_address,
            class_commitment,
            event_commitment,
            state_commitment,
            storage_commitment,
            transaction_commitment,
            starknet_version,
            // TODO: store block hash in-line.
            // This gets filled in by a separate query, but really should get stored as a column in
            // order to support truncated history.
            parent_hash: BlockHash::default(),
        };

        Ok(header)
    };

    let header = match block {
        BlockId::Latest => tx.inner().query_row(&sql, [], parse_row),
        BlockId::Number(number) => tx.inner().query_row(&sql, params![&number], parse_row),
        BlockId::Hash(hash) => tx.inner().query_row(&sql, params![&hash], parse_row),
    }
    .optional()
    .context("Querying for block header")?;

    let Some(mut header) = header else {
        return Ok(None);
    };

    // Fill in parent hash (unless we are at genesis in which case the current ZERO is correct).
    if header.number != BlockNumber::GENESIS {
        let parent_hash = tx
            .inner()
            .query_row(
                "SELECT hash FROM starknet_blocks WHERE number = ?",
                params![&(header.number - 1)],
                |row| row.get_block_hash(0),
            )
            .context("Querying parent hash")?;

        header.parent_hash = parent_hash;
    }

    Ok(Some(header))
}

pub(super) fn block_is_l1_accepted(tx: &Transaction<'_>, block: BlockId) -> anyhow::Result<bool> {
    let Some(l1_l2) = tx.l1_l2_pointer().context("Querying L1-L2 pointer")? else {
        return Ok(false);
    };

    let Some((block_number, _)) = tx.block_id(block).context("Fetching block number")? else {
        return Ok(false);
    };

    Ok(block_number <= l1_l2)
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        BlockTimestamp, ClassCommitment, ClassHash, EventCommitment, GasPrice, StateUpdate,
        TransactionCommitment,
    };

    use super::*;
    use crate::Connection;

    // Create test database filled with block headers.
    fn setup() -> (Connection, Vec<BlockHeader>) {
        let storage = crate::Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        // This intentionally does not use the builder so that we don't forget to test
        // any new fields that get added.
        //
        // Set unique values so we can be sure we are (de)serializing correctly.
        let storage_commitment = storage_commitment_bytes!(b"storage commitment genesis");
        let class_commitment = class_commitment_bytes!(b"class commitment genesis");

        let genesis = BlockHeader {
            hash: block_hash_bytes!(b"genesis hash"),
            parent_hash: BlockHash::ZERO,
            number: BlockNumber::GENESIS,
            timestamp: BlockTimestamp::new_or_panic(10),
            gas_price: GasPrice(32),
            sequencer_address: sequencer_address_bytes!(b"sequencer address genesis"),
            starknet_version: StarknetVersion::default(),
            class_commitment,
            event_commitment: event_commitment_bytes!(b"event commitment genesis"),
            // This needs to be calculated as this value is never actually stored directly.
            state_commitment: StateCommitment::calculate(storage_commitment, class_commitment),
            storage_commitment,
            transaction_commitment: transaction_commitment_bytes!(b"tx commitment genesis"),
        };
        let header1 = genesis
            .child_builder()
            .with_timestamp(BlockTimestamp::new_or_panic(12))
            .with_gas_price(GasPrice(34))
            .with_sequencer_address(sequencer_address_bytes!(b"sequencer address 1"))
            .with_event_commitment(event_commitment_bytes!(b"event commitment 1"))
            .with_class_commitment(class_commitment_bytes!(b"class commitment 1"))
            .with_storage_commitment(storage_commitment_bytes!(b"storage commitment 1"))
            .with_calculated_state_commitment()
            .with_transaction_commitment(transaction_commitment_bytes!(b"tx commitment 1"))
            .finalize_with_hash(block_hash_bytes!(b"block 1 hash"));

        let header2 = header1
            .child_builder()
            .with_gas_price(GasPrice(38))
            .with_timestamp(BlockTimestamp::new_or_panic(15))
            .with_sequencer_address(sequencer_address_bytes!(b"sequencer address 2"))
            .with_event_commitment(event_commitment_bytes!(b"event commitment 2"))
            .with_class_commitment(class_commitment_bytes!(b"class commitment 2"))
            .with_storage_commitment(storage_commitment_bytes!(b"storage commitment 2"))
            .with_calculated_state_commitment()
            .with_transaction_commitment(transaction_commitment_bytes!(b"tx commitment 2"))
            .finalize_with_hash(block_hash_bytes!(b"block 2 hash"));

        let headers = vec![genesis, header1, header2];
        for header in &headers {
            tx.insert_block_header(header).unwrap();
        }
        tx.commit().unwrap();

        (connection, headers)
    }

    #[test]
    fn get_latest() {
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();

        let result = tx.block_header(BlockId::Latest).unwrap().unwrap();
        let expected = headers.last().unwrap();

        assert_eq!(&result, expected);
    }

    #[test]
    fn get_by_number() {
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();

        for header in &headers {
            let result = tx.block_header(header.number.into()).unwrap().unwrap();
            assert_eq!(&result, header);
        }

        let past_head = headers.last().unwrap().number + 1;
        let result = tx.block_header(past_head.into()).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn get_by_hash() {
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();

        for header in &headers {
            let result = tx.block_header(header.hash.into()).unwrap().unwrap();
            assert_eq!(&result, header);
        }

        let invalid = block_hash_bytes!(b"invalid block hash");
        let result = tx.block_header(invalid.into()).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn get_works_with_null_fields() {
        // The migration introducing transaction, event and class commitments allowed them
        // to be NULL (and defaulted to NULL). This test ensures that these are correctly handled
        // and defaulted to ZERO.
        //
        // Starknet version was also allowed to be null which means that version_id can be null.
        // This should default to an empty version string now.
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();

        let target = headers.last().unwrap();

        // Overwrite the commitment fields to NULL.
        tx.inner().execute(
            r"UPDATE starknet_blocks
                SET transaction_commitment=NULL, event_commitment=NULL, class_commitment=NULL, version_id=NULL
                WHERE number=?",
            params![&target.number],
        )
        .unwrap();

        let mut expected = target.clone();
        expected.starknet_version = StarknetVersion::default();
        expected.transaction_commitment = TransactionCommitment::ZERO;
        expected.event_commitment = EventCommitment::ZERO;
        expected.class_commitment = ClassCommitment::ZERO;
        expected.state_commitment =
            StateCommitment::calculate(expected.storage_commitment, expected.class_commitment);

        let result = tx.block_header(target.number.into()).unwrap().unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn purge_block() {
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();
        let latest = headers.last().unwrap();

        // Add a class to test that purging a block unsets its block number;
        let cairo_hash = class_hash!("0x1234");
        tx.insert_cairo_class(cairo_hash, &[]).unwrap();
        tx.insert_state_update(
            latest.number,
            &StateUpdate::default().with_declared_cairo_class(cairo_hash),
        )
        .unwrap();

        tx.purge_block(latest.number).unwrap();

        let exists = tx.block_exists(latest.number.into()).unwrap();
        assert!(!exists);

        let class_exists = tx
            .class_definition_at(latest.number.into(), ClassHash(cairo_hash.0))
            .unwrap();
        assert_eq!(class_exists, None);
    }

    #[test]
    fn block_id() {
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();

        let target = headers.last().unwrap();
        let expected = Some((target.number, target.hash));

        let by_number = tx.block_id(target.number.into()).unwrap();
        assert_eq!(by_number, expected);

        let by_hash = tx.block_id(target.hash.into()).unwrap();
        assert_eq!(by_hash, expected);
    }

    #[test]
    fn block_is_l1_accepted() {
        let (mut connection, headers) = setup();
        let tx = connection.transaction().unwrap();

        // Mark the genesis header as L1 accepted.
        tx.update_l1_l2_pointer(Some(headers[0].number)).unwrap();

        let l1_by_hash = tx.block_is_l1_accepted(headers[0].hash.into()).unwrap();
        assert!(l1_by_hash);
        let l1_by_number = tx.block_is_l1_accepted(headers[0].number.into()).unwrap();
        assert!(l1_by_number);

        // The second block will therefore be L2 accepted.
        let l2_by_hash = tx.block_is_l1_accepted(headers[1].hash.into()).unwrap();
        assert!(!l2_by_hash);
        let l2_by_number = tx.block_is_l1_accepted(headers[1].number.into()).unwrap();
        assert!(!l2_by_number);
    }
}
