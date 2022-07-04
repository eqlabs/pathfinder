use anyhow::Context;
use rusqlite::Transaction;

pub(crate) fn migrate(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    // We need to check if this db needs fixing at all
    let update_is_not_required = {
        let mut stmt = transaction
            .prepare("SELECT sql FROM sqlite_schema where tbl_name = 'starknet_events'")
            .context("Preparing statement")?;
        let mut rows = stmt.query([]).context("Executing query")?;
        // Unwrap is safe because the schema for this table obviously contains more than
        // zero SQL statements, as can be seen in revision 7 migration.
        // The first statement of the schema for this table is the creation of the table
        // which could be missing the crucial action, which is ON DELETE CASCADE.
        rows.next()?
            .unwrap()
            .get_ref_unwrap("sql")
            .as_str()?
            .contains("ON DELETE CASCADE")
    };

    if update_is_not_required {
        return Ok(());
    }

    // When altering a table in a way that requires recreating it through copying and deletion
    // it is [recommended](https://www.sqlite.org/lang_altertable.html) to:
    // 1. create the new table with some temporary name
    // 2. copy the data from the old table
    // 3. drop the old table
    // 4. rename the new table
    // Instead of the opposite:
    // 1. rename the old table
    // 2. create the new table with the final name
    // 3. copy the data from the old table
    // 4. drop the old table
    //
    // Important notes:
    // 1. Triggers and indexes are dropped with the old `starknet_events` table,
    //    so they need to be recreated
    // 2. The virtual table `starknet_events_keys` remains unchanged but:
    //    - we need to make sure that the new `starknet_events` table
    //      [keeps the same rowids](https://www.sqlite.org/fts5.html#external_content_tables)
    //      as its older version
    //    - otherwise `starknet_events_keys` could refer invalid rowids
    //    - rendering future event queries unreliable
    transaction
        .execute_batch(
            r"
            CREATE TABLE starknet_events_v2 (
                block_number  INTEGER NOT NULL,
                idx INTEGER NOT NULL,
                transaction_hash BLOB NOT NULL,
                from_address BLOB NOT NULL,
                -- Keys are represented as base64 encoded strings separated by space
                keys TEXT,
                data BLOB,
                FOREIGN KEY(block_number) REFERENCES starknet_blocks(number)
                ON DELETE CASCADE
            );

            -- Copy rowids to be sure that starknet_events_keys still references valid rows
            INSERT INTO starknet_events_v2 (
                rowid,
                block_number,
                idx,
                transaction_hash,
                from_address,
                keys,
                data)

                SELECT starknet_events.rowid,
                    starknet_events.block_number,
                    starknet_events.idx,
                    starknet_events.transaction_hash,
                    starknet_events.from_address,
                    starknet_events.keys,
                    starknet_events.data

                FROM starknet_events;

            DROP TABLE starknet_events;

            ALTER TABLE starknet_events_v2 RENAME TO starknet_events;

            -- Event filters can specify ranges of blocks
            CREATE INDEX starknet_events_block_number ON starknet_events(block_number);

            -- Event filter can specify a contract address
            CREATE INDEX starknet_events_from_address ON starknet_events(from_address);

            CREATE TRIGGER starknet_events_ai
            AFTER INSERT ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(rowid, keys)
                VALUES (
                    new.rowid,
                    new.keys
                );
            END;

            CREATE TRIGGER starknet_events_ad
            AFTER DELETE ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
                VALUES (
                    'delete',
                    old.rowid,
                    old.keys
                );
            END;

            CREATE TRIGGER starknet_events_au
            AFTER UPDATE ON starknet_events
            BEGIN
                INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
                VALUES (
                    'delete',
                    old.rowid,
                    old.keys
                );
                INSERT INTO starknet_events_keys(rowid, keys)
                VALUES (
                    new.rowid,
                    new.keys
                );
            END;",
        )
        .context("Recreating the starknet_events table, related triggers and indexes")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    /// This statement simulates the bug that was present in one of the early DB snaphots
    /// for Goerli that was distributed to aid users with slow syncing
    const BUGGY_STARKNET_EVENTS_CREATE_STMT: &str = r"CREATE TABLE starknet_events (
        block_number  INTEGER NOT NULL,
        idx INTEGER NOT NULL,
        transaction_hash BLOB NOT NULL,
        from_address BLOB NOT NULL,
        -- Keys are represented as base64 encoded strings separated by space
        keys TEXT,
        data BLOB,
        FOREIGN KEY(block_number) REFERENCES starknet_blocks(number)
        ------------------------------------------------
        -- Warning! On delete cascade is missing here!
        ------------------------------------------------
    );

    -- Event filters can specify ranges of blocks
    CREATE INDEX starknet_events_block_number ON starknet_events(block_number);

    -- Event filter can specify a contract address
    CREATE INDEX starknet_events_from_address ON starknet_events(from_address);

    CREATE VIRTUAL TABLE starknet_events_keys
    USING fts5(
        keys,
        content='starknet_events',
        content_rowid='rowid',
        tokenize='ascii'
    );

    CREATE TRIGGER starknet_events_ai
    AFTER INSERT ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.rowid,
            new.keys
        );
    END;

    CREATE TRIGGER starknet_events_ad
    AFTER DELETE ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
        VALUES (
            'delete',
            old.rowid,
            old.keys
        );
    END;

    CREATE TRIGGER starknet_events_au
    AFTER UPDATE ON starknet_events
    BEGIN
        INSERT INTO starknet_events_keys(starknet_events_keys, rowid, keys)
        VALUES (
            'delete',
            old.rowid,
            old.keys
        );
        INSERT INTO starknet_events_keys(rowid, keys)
        VALUES (
            new.rowid,
            new.keys
        );
    END;";

    mod empty {
        use crate::storage::schema::{self};
        use rusqlite::Connection;

        #[test]
        fn correct_schema_in_rev7() {
            let mut conn = Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            schema::revision_0001::migrate(&transaction).unwrap();
            schema::revision_0002::migrate(&transaction).unwrap();
            schema::revision_0003::migrate(&transaction).unwrap();
            schema::revision_0004::migrate(&transaction).unwrap();
            schema::revision_0005::migrate(&transaction).unwrap();
            schema::revision_0006::migrate(&transaction).unwrap();
            schema::revision_0007::migrate(&transaction).unwrap();
            schema::revision_0008::migrate(&transaction).unwrap();
            schema::revision_0009::migrate(&transaction).unwrap();

            super::super::migrate(&transaction).unwrap();
        }

        #[test]
        fn buggy_schema_in_rev7() {
            let mut conn = Connection::open_in_memory().unwrap();
            let transaction = conn.transaction().unwrap();

            schema::revision_0001::migrate(&transaction).unwrap();
            schema::revision_0002::migrate(&transaction).unwrap();
            schema::revision_0003::migrate(&transaction).unwrap();
            schema::revision_0004::migrate(&transaction).unwrap();
            schema::revision_0005::migrate(&transaction).unwrap();
            schema::revision_0006::migrate(&transaction).unwrap();
            schema::revision_0007::migrate_with(
                &transaction,
                super::BUGGY_STARKNET_EVENTS_CREATE_STMT,
            )
            .unwrap();
            schema::revision_0008::migrate(&transaction).unwrap();
            schema::revision_0009::migrate(&transaction).unwrap();

            super::super::migrate(&transaction).unwrap();
        }
    }

    mod stateful {
        use rusqlite::{self, Connection};
        use stark_hash::StarkHash;

        use crate::{
            core::{
                ContractAddress, EventData, EventKey, GlobalRoot, StarknetBlockHash,
                StarknetBlockNumber, StarknetBlockTimestamp, StarknetTransactionHash,
            },
            sequencer::reply::transaction::{self, Event, Transaction},
            storage::{schema, state::PageOfEvents, StarknetEmittedEvent, StarknetEventFilter},
        };

        // This is a copy of the structures and functions as of revision 7,
        // which allows us to simulate the conditions in which the bug
        // used to occur.
        mod storage_rev7 {
            use super::*;
            use rusqlite::named_params;

            #[derive(Debug, Clone, PartialEq)]
            pub struct StarknetBlock {
                pub number: StarknetBlockNumber,
                pub hash: StarknetBlockHash,
                pub root: GlobalRoot,
                pub timestamp: StarknetBlockTimestamp,
            }

            pub struct StarknetBlocksTable;

            impl StarknetBlocksTable {
                pub fn insert(
                    connection: &Connection,
                    block: &StarknetBlock,
                ) -> anyhow::Result<()> {
                    connection.execute(
                        r"INSERT INTO starknet_blocks ( number,  hash,  root,  timestamp)
                                               VALUES (:number, :hash, :root, :timestamp)",
                        named_params! {
                            ":number": block.number.0,
                            ":hash": block.hash.0.as_be_bytes(),
                            ":root": block.root.0.as_be_bytes(),
                            ":timestamp": block.timestamp.0,
                        },
                    )?;

                    Ok(())
                }

                /// Deletes all rows from __head down-to reorg_tail__
                /// i.e. it deletes all rows where `block number >= reorg_tail`.
                pub fn reorg(
                    connection: &Connection,
                    reorg_tail: StarknetBlockNumber,
                ) -> anyhow::Result<()> {
                    connection.execute(
                        "DELETE FROM starknet_blocks WHERE number >= ?",
                        rusqlite::params![reorg_tail.0],
                    )?;
                    Ok(())
                }

                /// Returns the [number](StarknetBlockNumber) of the latest block.
                pub fn get_latest_number(
                    connection: &Connection,
                ) -> anyhow::Result<Option<StarknetBlockNumber>> {
                    use anyhow::Context;

                    let mut statement = connection.prepare(
                        "SELECT number FROM starknet_blocks ORDER BY number DESC LIMIT 1",
                    )?;
                    let mut rows = statement.query([])?;
                    let row = rows.next().context("Iterate rows")?;
                    match row {
                        Some(row) => {
                            let number = row.get_ref_unwrap("number").as_i64().unwrap() as u64;
                            let number = StarknetBlockNumber(number);
                            Ok(Some(number))
                        }
                        None => Ok(None),
                    }
                }
            }

            pub struct StarknetEventsTable;
            impl StarknetEventsTable {
                pub fn event_data_to_bytes(data: &[EventData]) -> Vec<u8> {
                    data.iter()
                        .flat_map(|e| (*e.0.as_be_bytes()).into_iter())
                        .collect()
                }

                fn event_key_to_base64_string(key: &EventKey) -> String {
                    base64::encode(key.0.as_be_bytes())
                }

                pub fn event_keys_to_base64_strings(keys: &[EventKey]) -> String {
                    // TODO: we really should be using Iterator::intersperse() here once it's stabilized.
                    let keys: Vec<String> =
                        keys.iter().map(Self::event_key_to_base64_string).collect();
                    keys.join(" ")
                }

                pub fn insert_events(
                    connection: &Connection,
                    block_number: StarknetBlockNumber,
                    transaction: &transaction::Transaction,
                    events: &[transaction::Event],
                ) -> anyhow::Result<()> {
                    use anyhow::Context;

                    if transaction.contract_address.is_none() && !events.is_empty() {
                        anyhow::bail!("Declare transactions cannot emit events");
                    }

                    for (idx, event) in events.iter().enumerate() {
                        connection
                        .execute(
                            r"INSERT INTO starknet_events ( block_number,  idx,  transaction_hash,  from_address,  keys,  data)
                                                   VALUES (:block_number, :idx, :transaction_hash, :from_address, :keys, :data)",
                            rusqlite::named_params![
                                ":block_number": block_number.0,
                                ":idx": idx,
                                ":transaction_hash": &transaction.transaction_hash.0.as_be_bytes()[..],
                                ":from_address": &event.from_address.0.as_be_bytes()[..],
                                ":keys": Self::event_keys_to_base64_strings(&event.keys),
                                ":data": Self::event_data_to_bytes(&event.data),
                            ],
                        )
                        .context("Insert events into events table")?;
                    }
                    Ok(())
                }

                pub(crate) const PAGE_SIZE_LIMIT: usize = 1024;

                pub fn get_events(
                    connection: &Connection,
                    filter: &StarknetEventFilter,
                ) -> anyhow::Result<PageOfEvents> {
                    use anyhow::Context;

                    let mut base_query =
            r#"SELECT
                  block_number,
                  starknet_blocks.hash as block_hash,
                  transaction_hash,
                  from_address,
                  data,
                  starknet_events.keys as keys
               FROM starknet_events
               INNER JOIN starknet_blocks ON starknet_blocks.number = starknet_events.block_number "#
                .to_string();
                    let mut where_statement_parts: Vec<&'static str> = Vec::new();
                    let mut params: Vec<(&str, &dyn rusqlite::ToSql)> = Vec::new();

                    // filter on block range
                    match (&filter.from_block, &filter.to_block) {
                        (Some(from_block), Some(to_block)) => {
                            where_statement_parts
                                .push("block_number BETWEEN :from_block AND :to_block");
                            params.push((":from_block", &from_block.0));
                            params.push((":to_block", &to_block.0));
                        }
                        (Some(from_block), None) => {
                            where_statement_parts.push("block_number >= :from_block");
                            params.push((":from_block", &from_block.0));
                        }
                        (None, Some(to_block)) => {
                            where_statement_parts.push("block_number <= :to_block");
                            params.push((":to_block", &to_block.0));
                        }
                        (None, None) => {}
                    }

                    // filter on contract address
                    if let Some(contract_address) = &filter.contract_address {
                        where_statement_parts.push("from_address = :contract_address");
                        params.push((":contract_address", contract_address.0.as_be_bytes()))
                    }

                    // Filter on keys: this is using an FTS5 full-text index (virtual table) on the keys.
                    // The idea is that we convert keys to a space-separated list of Bas64 encoded string
                    // representation and then use the full-text index to find events matching the events.
                    // HACK: make sure key_fts_expression lives long enough
                    let key_fts_expression;
                    if !filter.keys.is_empty() {
                        let base64_keys: Vec<String> = filter
                            .keys
                            .iter()
                            .map(|key| format!("\"{}\"", Self::event_key_to_base64_string(key)))
                            .collect();
                        key_fts_expression = base64_keys.join(" OR ");

                        base_query.push_str("INNER JOIN starknet_events_keys ON starknet_events.rowid = starknet_events_keys.rowid");
                        where_statement_parts.push("starknet_events_keys.keys MATCH :events_match");
                        params.push((":events_match", &key_fts_expression));
                    }

                    // Paging
                    if filter.page_size > Self::PAGE_SIZE_LIMIT {
                        return Err(crate::storage::EventFilterError::PageSizeTooBig(
                            Self::PAGE_SIZE_LIMIT,
                        )
                        .into());
                    }
                    if filter.page_size < 1 {
                        anyhow::bail!("Invalid page size");
                    }
                    let offset = filter.page_number * filter.page_size;
                    // We have to be able to decide if there are more events. We request one extra event
                    // above the requested page size, so that we can decide.
                    let limit = filter.page_size + 1;
                    params.push((":limit", &limit));
                    params.push((":offset", &offset));

                    let query = if where_statement_parts.is_empty() {
                        format!(
                "{} ORDER BY block_number, transaction_hash, idx LIMIT :limit OFFSET :offset",
                base_query
            )
                    } else {
                        format!(
                "{} WHERE {} ORDER BY block_number, transaction_hash, idx LIMIT :limit OFFSET :offset",
                base_query,
                where_statement_parts.join(" AND "),
            )
                    };

                    let mut statement =
                        connection.prepare(&query).context("Preparing SQL query")?;
                    let mut rows = statement
                        .query(params.as_slice())
                        .context("Executing SQL query")?;

                    let mut is_last_page = true;
                    let mut emitted_events = Vec::new();
                    while let Some(row) = rows.next().context("Fetching next event")? {
                        let block_number =
                            row.get_ref_unwrap("block_number").as_i64().unwrap() as u64;
                        let block_number = StarknetBlockNumber(block_number);

                        let block_hash = row.get_ref_unwrap("block_hash").as_blob().unwrap();
                        let block_hash = StarkHash::from_be_slice(block_hash).unwrap();
                        let block_hash = StarknetBlockHash(block_hash);

                        let transaction_hash =
                            row.get_ref_unwrap("transaction_hash").as_blob().unwrap();
                        let transaction_hash = StarkHash::from_be_slice(transaction_hash).unwrap();
                        let transaction_hash = StarknetTransactionHash(transaction_hash);

                        let from_address = row.get_ref_unwrap("from_address").as_blob().unwrap();
                        let from_address = StarkHash::from_be_slice(from_address).unwrap();
                        let from_address = ContractAddress(from_address);

                        let data = row.get_ref_unwrap("data").as_blob().unwrap();
                        let data: Vec<_> = data
                            .chunks_exact(32)
                            .map(|data| {
                                let data = StarkHash::from_be_slice(data).unwrap();
                                EventData(data)
                            })
                            .collect();

                        let keys = row.get_ref_unwrap("keys").as_str().unwrap();
                        let keys: Vec<_> = keys
                            .split(' ')
                            .map(|key| {
                                let key = StarkHash::from_be_slice(&base64::decode(key).unwrap())
                                    .unwrap();
                                EventKey(key)
                            })
                            .collect();

                        if emitted_events.len() == filter.page_size {
                            // We already have a full page, and are just fetching the extra event
                            // This means that there are more pages.
                            is_last_page = false;
                        } else {
                            let event = StarknetEmittedEvent {
                                data,
                                from_address,
                                keys,
                                block_hash,
                                block_number,
                                transaction_hash,
                            };
                            emitted_events.push(event);
                        }
                    }

                    Ok(PageOfEvents {
                        events: emitted_events,
                        is_last_page,
                    })
                }
            }
        }

        /// This is a test helper function which runs a stateful scenario of the migration
        /// with the revision 7 migration being customisable via a closure provided by the caller
        fn run_stateful_scenario<Fn: for<'a> FnOnce(&rusqlite::Transaction<'a>)>(
            revision_0007_migrate_fn: Fn,
        ) {
            let mut connection = Connection::open("test.sqlite").unwrap();
            // let mut connection = Connection::open_in_memory().unwrap();
            let transaction = connection.transaction().unwrap();

            // 1. Migrate the db up to rev7
            schema::revision_0001::migrate(&transaction).unwrap();
            schema::revision_0002::migrate(&transaction).unwrap();
            schema::revision_0003::migrate(&transaction).unwrap();
            schema::revision_0004::migrate(&transaction).unwrap();
            schema::revision_0005::migrate(&transaction).unwrap();
            schema::revision_0006::migrate(&transaction).unwrap();
            revision_0007_migrate_fn(&transaction);

            // 2. Insert some data that would cause the regression
            let block0_number = StarknetBlockNumber(0);
            let block1_number = StarknetBlockNumber(1);
            let block0_hash = StarknetBlockHash(StarkHash::from_be_slice(b"block 1 hash").unwrap());
            let block0 = storage_rev7::StarknetBlock {
                hash: block0_hash,
                number: block0_number,
                root: GlobalRoot(StarkHash::from_be_slice(b"root 0").unwrap()),
                timestamp: StarknetBlockTimestamp(0),
            };
            let block1 = storage_rev7::StarknetBlock {
                hash: StarknetBlockHash(StarkHash::from_be_slice(b"block 1 hash").unwrap()),
                number: block1_number,
                root: GlobalRoot(StarkHash::from_be_slice(b"root 1").unwrap()),
                timestamp: StarknetBlockTimestamp(1),
            };
            let contract0_address =
                ContractAddress(StarkHash::from_be_slice(b"contract 0 address").unwrap());
            let contract1_address =
                ContractAddress(StarkHash::from_be_slice(b"contract 1 address").unwrap());
            let transaction0_hash =
                StarknetTransactionHash(StarkHash::from_be_slice(b"transaction 0 hash").unwrap());
            let transaction0 = Transaction {
                calldata: None,
                class_hash: None,
                constructor_calldata: None,
                contract_address: Some(contract0_address),
                contract_address_salt: None,
                entry_point_selector: None,
                entry_point_type: None,
                max_fee: None,
                nonce: None,
                sender_address: None,
                signature: None,
                transaction_hash: transaction0_hash,
                r#type: transaction::Type::Deploy,
                version: None,
            };
            let mut transaction1 = transaction0.clone();
            transaction1.transaction_hash =
                StarknetTransactionHash(StarkHash::from_be_slice(b"transaction 1 hash").unwrap());
            let event0_key = EventKey(StarkHash::from_be_slice(b"event 0 key").unwrap());
            let event1_key = EventKey(StarkHash::from_be_slice(b"event 1 key").unwrap());
            let event0_data = EventData(StarkHash::from_be_slice(b"event 0 data").unwrap());
            let event0 = Event {
                data: vec![event0_data],
                from_address: contract0_address,
                keys: vec![event0_key],
            };
            let event1 = Event {
                data: vec![EventData(
                    StarkHash::from_be_slice(b"event 1 data").unwrap(),
                )],
                from_address: contract1_address,
                keys: vec![event1_key],
            };

            storage_rev7::StarknetBlocksTable::insert(&transaction, &block0).unwrap();
            storage_rev7::StarknetEventsTable::insert_events(
                &transaction,
                block0_number,
                &transaction0,
                &[event0],
            )
            .unwrap();
            storage_rev7::StarknetBlocksTable::insert(&transaction, &block1).unwrap();
            storage_rev7::StarknetEventsTable::insert_events(
                &transaction,
                block1_number,
                &transaction1,
                &[event1],
            )
            .unwrap();

            // 3. Migrate up to rev9
            schema::revision_0008::migrate(&transaction).unwrap();
            schema::revision_0009::migrate(&transaction).unwrap();

            // 4. Migration to rev10 should fix the problem
            super::super::migrate(&transaction).unwrap();

            // 5. Perform the operation that used to trigger the failure and make sure it does not occur now
            storage_rev7::StarknetBlocksTable::reorg(&transaction, block1_number).unwrap();

            assert_eq!(
                storage_rev7::StarknetBlocksTable::get_latest_number(&transaction)
                    .unwrap()
                    .unwrap(),
                block0_number
            );
            let filter0 = StarknetEventFilter {
                contract_address: None,
                from_block: None,
                to_block: None,
                keys: vec![event0_key],
                page_size: 10,
                page_number: 0,
            };
            let filter1 = StarknetEventFilter {
                contract_address: None,
                from_block: None,
                to_block: None,
                keys: vec![event1_key],
                page_size: 10,
                page_number: 0,
            };
            assert_eq!(
                storage_rev7::StarknetEventsTable::get_events(&transaction, &filter0).unwrap(),
                PageOfEvents {
                    events: vec![StarknetEmittedEvent {
                        block_hash: block0_hash,
                        block_number: block0_number,
                        data: vec![event0_data],
                        from_address: contract0_address,
                        keys: vec![event0_key],
                        transaction_hash: transaction0_hash,
                    }],
                    is_last_page: true
                }
            );
            assert!(
                storage_rev7::StarknetEventsTable::get_events(&transaction, &filter1)
                    .unwrap()
                    .events
                    .is_empty()
            );
        }

        #[test]
        fn correct_schema_in_rev7() {
            run_stateful_scenario(|tx| {
                schema::revision_0007::migrate(tx).unwrap();
            });
        }

        #[test]
        fn buggy_schema_in_rev7() {
            run_stateful_scenario(|tx| {
                schema::revision_0007::migrate_with(tx, super::BUGGY_STARKNET_EVENTS_CREATE_STMT)
                    .unwrap();
            });
        }

        #[test]
        fn virtual_table_still_references_valid_data() {
            use crate::storage::schema;
            use anyhow::Context;

            let mut connection = Connection::open_in_memory().unwrap();
            let transaction = connection.transaction().unwrap();

            // 0. Initial migrations happen
            schema::revision_0001::migrate(&transaction).unwrap();
            schema::revision_0002::migrate(&transaction).unwrap();
            schema::revision_0003::migrate(&transaction).unwrap();
            schema::revision_0004::migrate(&transaction).unwrap();
            schema::revision_0005::migrate(&transaction).unwrap();
            schema::revision_0006::migrate(&transaction).unwrap();

            // 1. There is a buggy schema in rev7
            schema::revision_0007::migrate_with(
                &transaction,
                super::BUGGY_STARKNET_EVENTS_CREATE_STMT,
            )
            .unwrap();

            // 2. Simulate rowids of the old `starknet_events` table to be different from
            // the new, migrated `starknet_events` table
            let emitted_events = schema::fixtures::setup_events(&transaction);
            let changed = transaction
                .execute(r"UPDATE starknet_events SET rowid = rowid + 1000000", [])
                .context("Force arbitrary rowids")
                .unwrap();
            assert_eq!(changed, schema::fixtures::NUM_TXNS);

            let expected_event = &emitted_events[1];
            let filter = StarknetEventFilter {
                from_block: Some(expected_event.block_number),
                to_block: Some(expected_event.block_number),
                contract_address: Some(expected_event.from_address),
                // we're using a key which is present in _all_ events
                keys: vec![EventKey(StarkHash::from_hex_str("deadbeef").unwrap())],
                page_size: schema::fixtures::NUM_TXNS,
                page_number: 0,
            };

            // 3. Getting events works just fine, the result relies on the data in `starknet_events_keys` virtual table
            let events =
                storage_rev7::StarknetEventsTable::get_events(&transaction, &filter).unwrap();
            assert_eq!(
                events,
                PageOfEvents {
                    events: vec![expected_event.clone()],
                    is_last_page: true
                }
            );

            // 4. More migrations happen
            schema::revision_0008::migrate(&transaction).unwrap();
            schema::revision_0009::migrate(&transaction).unwrap();

            // 5. Eventually schema from rev7 gets fixed, but we need to make sure that the virtual
            // table `starknet_events_keys` still contains data which references valid rowids
            // in the new `starknet_events` table
            schema::revision_0010::migrate(&transaction).unwrap();

            let events =
                storage_rev7::StarknetEventsTable::get_events(&transaction, &filter).unwrap();
            assert_eq!(
                events,
                PageOfEvents {
                    events: vec![expected_event.clone()],
                    is_last_page: true
                }
            );
        }
    }
}
