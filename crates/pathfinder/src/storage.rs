//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

mod contract;
mod ethereum;
#[cfg(test)]
pub(crate) mod fixtures;
pub mod merkle_tree;
mod schema;
mod state;

use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use contract::{ContractCodeTable, ContractsTable};
pub use ethereum::{EthereumBlocksTable, EthereumTransactionsTable};
pub use state::{
    CanonicalBlocksTable, ContractsStateTable, EventFilterError, L1StateTable, L1TableBlockId,
    RefsTable, StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable, StarknetEmittedEvent,
    StarknetEventFilter, StarknetEventsTable, StarknetStateUpdatesTable, StarknetTransactionsTable,
};

use anyhow::Context;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

/// Sqlite key used for the PRAGMA user version.
const VERSION_KEY: &str = "user_version";

type PooledConnection = r2d2::PooledConnection<SqliteConnectionManager>;

/// Specifies the [journal mode](https://sqlite.org/pragma.html#pragma_journal_mode)
/// of the [Storage].
pub enum JournalMode {
    Rollback,
    WAL,
}

/// Used to create [Connection's](Connection) to the pathfinder database.
///
/// Intended usage:
/// - Use [Storage::migrate] to create the app's database.
/// - Pass the [Storage] (or clones thereof) to components which require database access.
/// - Use [Storage::connection] to create connection's to the database, which can in turn
///   be used to interact with the various [tables](self).
#[derive(Clone)]
pub struct Storage(Inner);

#[derive(Clone)]
struct Inner {
    /// Uses [`Arc`] to allow _shallow_ [Storage] cloning
    database_path: Arc<PathBuf>,
    pool: Pool<SqliteConnectionManager>,
}

impl Storage {
    /// Performs database schema migration and returns a new [Storage].
    ///
    /// This should be called __once__ at the start of the application,
    /// and passed to the various components which require access to the database.
    ///
    /// May be cloned safely.
    pub fn migrate(database_path: PathBuf, journal_mode: JournalMode) -> anyhow::Result<Self> {
        let manager = SqliteConnectionManager::file(&database_path);
        let pool = Pool::builder().build(manager)?;

        let mut conn = pool.get()?;
        match journal_mode {
            JournalMode::Rollback => conn
                .pragma_update(None, "journal_mode", "DELETE")
                .context("Disabling WAL journal mode")?,
            JournalMode::WAL => {
                conn.pragma_update(None, "journal_mode", "WAL")
                    .context("Enabling WAL journal mode")?;
                // set journal size limit to 1 GB
                conn.pragma_update(
                    None,
                    "journal_size_limit",
                    (1024usize * 1024 * 1024).to_string(),
                )
                .context("Set journal size limit")?;
            }
        }
        migrate_database(&mut conn).context("Migrate database")?;

        let inner = Inner {
            database_path: Arc::new(database_path),
            pool,
        };

        let storage = Storage(inner);

        Ok(storage)
    }

    /// Returns a new Sqlite [Connection] to the database.
    pub fn connection(&self) -> anyhow::Result<PooledConnection> {
        let conn = self.0.pool.get()?;
        Ok(conn)
    }

    /// Convenience function for tests to create an in-memory database.
    /// Equivalent to [Storage::migrate] with an in-memory backed database.
    // No longer cfg(test) because needed in benchmarks
    pub fn in_memory() -> anyhow::Result<Self> {
        // Create a unique database name so that they are not shared between
        // concurrent tests. i.e. Make every in-mem Storage unique.
        lazy_static::lazy_static!(
            static ref COUNT: std::sync::Mutex<u64> = Default::default();
        );
        let unique_mem_db = {
            let mut count = COUNT.lock().unwrap();
            // &cache=shared allows other threads to see and access the inmemory database
            let unique_mem_db = format!("file:memdb{}?mode=memory&cache=shared", count);
            *count += 1;
            unique_mem_db
        };

        let database_path = PathBuf::from(unique_mem_db);

        Self::migrate(database_path, JournalMode::Rollback)
    }

    pub fn path(&self) -> &Path {
        &self.0.database_path
    }
}

/// Migrates the database to the latest version. This __MUST__ be called
/// at the beginning of the application.
fn migrate_database(connection: &mut Connection) -> anyhow::Result<()> {
    enable_foreign_keys(connection).context("Failed to enable foreign key support")?;
    let version = schema_version(connection)?;
    let migrations = schema::migrations();

    // Check that the database is not newer than this application knows of.
    anyhow::ensure!(
        version <= migrations.len(),
        "Database version is newer than this application ({} > {})",
        version,
        migrations.len()
    );

    // Sequentially apply each missing migration.
    migrations
        .iter()
        .enumerate()
        .skip(version)
        .try_for_each(|(from, migration)| {
            let mut do_migration = || -> anyhow::Result<()> {
                let transaction = connection
                    .transaction()
                    .context("Create database transaction")?;
                migration(&transaction)?;
                transaction
                    .pragma_update(None, VERSION_KEY, from + 1)
                    .context("Failed to update the schema version number")?;
                transaction
                    .commit()
                    .context("Commit migration transaction")?;

                Ok(())
            };

            do_migration().with_context(|| format!("Migrating from {from}"))
        })?;

    Ok(())
}
/// Returns the current schema version of the existing database,
/// or `0` if database does not yet exist.
fn schema_version(connection: &Connection) -> anyhow::Result<usize> {
    // We store the schema version in the Sqlite provided PRAGMA "user_version",
    // which stores an INTEGER and defaults to 0.
    let version = connection.query_row(
        &format!("SELECT {} FROM pragma_user_version;", VERSION_KEY),
        [],
        |row| row.get::<_, usize>(0),
    )?;
    Ok(version)
}

/// Enables foreign key support for the database.
fn enable_foreign_keys(connection: &Connection) -> anyhow::Result<()> {
    use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
    connection.set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_utils {
    use super::{
        StarknetBlock, StarknetBlocksTable, StarknetEmittedEvent, StarknetTransactionsTable,
        Storage,
    };
    use pathfinder_common::{
        starkhash, CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
        EntryPoint, EventData, EventKey, Fee, GasPrice, GlobalRoot, SequencerAddress,
        StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp, StarknetTransactionHash,
        StarknetTransactionIndex, TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use stark_hash::StarkHash;
    use starknet_gateway_types::reply::transaction::{
        self, DeclareTransaction, DeployTransaction, EntryPointType, InvokeTransaction,
        InvokeTransactionV0,
    };
    use web3::types::{H128, H256};

    pub(crate) const NUM_BLOCKS: usize = 4;
    pub(crate) const TRANSACTIONS_PER_BLOCK: usize = 15;
    const INVOKE_TRANSACTIONS_PER_BLOCK: usize = 5;
    const DEPLOY_TRANSACTIONS_PER_BLOCK: usize = 5;
    const DECLARE_TRANSACTIONS_PER_BLOCK: usize =
        TRANSACTIONS_PER_BLOCK - (INVOKE_TRANSACTIONS_PER_BLOCK + DEPLOY_TRANSACTIONS_PER_BLOCK);
    pub(crate) const EVENTS_PER_BLOCK: usize =
        INVOKE_TRANSACTIONS_PER_BLOCK + DECLARE_TRANSACTIONS_PER_BLOCK;
    pub(crate) const NUM_TRANSACTIONS: usize = NUM_BLOCKS * TRANSACTIONS_PER_BLOCK;
    pub(crate) const NUM_EVENTS: usize = NUM_BLOCKS * EVENTS_PER_BLOCK;

    /// Creates a set of consecutive [StarknetBlock]s starting from L2 genesis,
    /// with arbitrary other values.
    pub(crate) fn create_blocks() -> [StarknetBlock; NUM_BLOCKS] {
        (0..NUM_BLOCKS)
            .map(|i| StarknetBlock {
                number: StarknetBlockNumber::GENESIS + i as u64,
                hash: StarknetBlockHash(StarkHash::from_hex_str(&"a".repeat(i + 3)).unwrap()),
                root: GlobalRoot(StarkHash::from_hex_str(&"f".repeat(i + 3)).unwrap()),
                timestamp: StarknetBlockTimestamp::new_or_panic(i as u64 + 500),
                gas_price: GasPrice::from(i as u64),
                sequencer_address: SequencerAddress(StarkHash::from_be_slice(&[i as u8]).unwrap()),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Creates a set of test transactions and receipts.
    pub(crate) fn create_transactions_and_receipts(
    ) -> [(transaction::Transaction, transaction::Receipt); NUM_TRANSACTIONS] {
        let transactions = (0..NUM_TRANSACTIONS).map(|i| match i % TRANSACTIONS_PER_BLOCK {
            x if x < INVOKE_TRANSACTIONS_PER_BLOCK => {
                transaction::Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                    calldata: vec![CallParam(
                        StarkHash::from_hex_str(&"0".repeat(i + 3)).unwrap(),
                    )],
                    contract_address: ContractAddress::new_or_panic(
                        StarkHash::from_hex_str(&"1".repeat(i + 3)).unwrap(),
                    ),
                    entry_point_selector: EntryPoint(
                        StarkHash::from_hex_str(&"2".repeat(i + 3)).unwrap(),
                    ),
                    entry_point_type: Some(if i & 1 == 0 {
                        EntryPointType::External
                    } else {
                        EntryPointType::L1Handler
                    }),
                    max_fee: Fee(H128::zero()),
                    signature: vec![TransactionSignatureElem(
                        StarkHash::from_hex_str(&"3".repeat(i + 3)).unwrap(),
                    )],
                    transaction_hash: StarknetTransactionHash(
                        StarkHash::from_hex_str(&"4".repeat(i + 3)).unwrap(),
                    ),
                }))
            }
            x if (INVOKE_TRANSACTIONS_PER_BLOCK
                ..INVOKE_TRANSACTIONS_PER_BLOCK + DEPLOY_TRANSACTIONS_PER_BLOCK)
                .contains(&x) =>
            {
                transaction::Transaction::Deploy(DeployTransaction {
                    contract_address: ContractAddress::new_or_panic(
                        StarkHash::from_hex_str(&"5".repeat(i + 3)).unwrap(),
                    ),
                    contract_address_salt: ContractAddressSalt(
                        StarkHash::from_hex_str(&"6".repeat(i + 3)).unwrap(),
                    ),
                    class_hash: ClassHash(StarkHash::from_hex_str(&"7".repeat(i + 3)).unwrap()),
                    constructor_calldata: vec![ConstructorParam(
                        StarkHash::from_hex_str(&"8".repeat(i + 3)).unwrap(),
                    )],
                    transaction_hash: StarknetTransactionHash(
                        StarkHash::from_hex_str(&"9".repeat(i + 3)).unwrap(),
                    ),
                    version: TransactionVersion(web3::types::H256::zero()),
                })
            }
            _ => transaction::Transaction::Declare(DeclareTransaction {
                class_hash: ClassHash(StarkHash::from_hex_str(&"a".repeat(i + 3)).unwrap()),
                max_fee: Fee(H128::zero()),
                nonce: TransactionNonce(StarkHash::from_hex_str(&"b".repeat(i + 3)).unwrap()),
                sender_address: ContractAddress::new_or_panic(
                    StarkHash::from_hex_str(&"c".repeat(i + 3)).unwrap(),
                ),
                signature: vec![TransactionSignatureElem(
                    StarkHash::from_hex_str(&"d".repeat(i + 3)).unwrap(),
                )],
                transaction_hash: StarknetTransactionHash(
                    StarkHash::from_hex_str(&"e".repeat(i + 3)).unwrap(),
                ),
                version: TransactionVersion(H256::zero()),
            }),
        });

        let tx_receipt = transactions.enumerate().map(|(i, tx)| {
            let receipt = transaction::Receipt {
                actual_fee: None,
                events: if i % TRANSACTIONS_PER_BLOCK < EVENTS_PER_BLOCK {
                    vec![transaction::Event {
                        from_address: ContractAddress::new_or_panic(
                            StarkHash::from_hex_str(&"2".repeat(i + 3)).unwrap(),
                        ),
                        data: vec![EventData(
                            StarkHash::from_hex_str(&"c".repeat(i + 3)).unwrap(),
                        )],
                        keys: vec![
                            EventKey(StarkHash::from_hex_str(&"d".repeat(i + 3)).unwrap()),
                            EventKey(starkhash!("deadbeef")),
                        ],
                    }]
                } else {
                    vec![]
                },
                execution_resources: Some(transaction::ExecutionResources {
                    builtin_instance_counter:
                        transaction::execution_resources::BuiltinInstanceCounter::Empty(
                            transaction::execution_resources::EmptyBuiltinInstanceCounter {},
                        ),
                    n_steps: i as u64 + 987,
                    n_memory_holes: i as u64 + 1177,
                }),
                l1_to_l2_consumed_message: None,
                l2_to_l1_messages: Vec::new(),
                transaction_hash: tx.hash(),
                transaction_index: StarknetTransactionIndex::new_or_panic(i as u64 + 2311),
            };

            (tx, receipt)
        });

        tx_receipt.collect::<Vec<_>>().try_into().unwrap()
    }

    /// Creates a set of emitted events from given blocks and transactions.
    pub(crate) fn extract_events(
        blocks: &[StarknetBlock],
        transactions_and_receipts: &[(transaction::Transaction, transaction::Receipt)],
    ) -> Vec<StarknetEmittedEvent> {
        transactions_and_receipts
            .iter()
            .enumerate()
            .filter_map(|(i, (txn, receipt))| {
                if i % TRANSACTIONS_PER_BLOCK < EVENTS_PER_BLOCK {
                    let event = &receipt.events[0];
                    let block = &blocks[i / TRANSACTIONS_PER_BLOCK];

                    Some(StarknetEmittedEvent {
                        data: event.data.clone(),
                        from_address: event.from_address,
                        keys: event.keys.clone(),
                        block_hash: block.hash,
                        block_number: block.number,
                        transaction_hash: txn.hash(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Creates a storage instance in memory with a set of expected emitted events
    pub(crate) fn setup_test_storage() -> (Storage, Vec<StarknetEmittedEvent>) {
        use crate::storage::CanonicalBlocksTable;

        let storage = Storage::in_memory().unwrap();
        let mut connection = storage.connection().unwrap();
        let tx = connection.transaction().unwrap();

        let blocks = create_blocks();
        let transactions_and_receipts = create_transactions_and_receipts();

        for (i, block) in blocks.iter().enumerate() {
            StarknetBlocksTable::insert(&tx, block, None).unwrap();
            CanonicalBlocksTable::insert(&tx, block.number, block.hash).unwrap();
            StarknetTransactionsTable::upsert(
                &tx,
                block.hash,
                block.number,
                &transactions_and_receipts
                    [i * TRANSACTIONS_PER_BLOCK..(i + 1) * TRANSACTIONS_PER_BLOCK],
            )
            .unwrap();
        }

        tx.commit().unwrap();

        let events = extract_events(&blocks, &transactions_and_receipts);

        (storage, events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_defaults_to_zero() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        let version = schema_version(&transaction).unwrap();
        assert_eq!(version, 0);
    }

    #[test]
    fn full_migration() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        migrate_database(&mut conn).unwrap();
        let version = schema_version(&conn).unwrap();
        let expected = schema::migrations().len();
        assert_eq!(version, expected);
    }

    #[test]
    fn migration_fails_if_db_is_newer() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();

        // Force the schema to a newer version
        let current_version = schema::migrations().len();
        conn.pragma_update(None, VERSION_KEY, current_version + 1)
            .unwrap();

        // Migration should fail.
        migrate_database(&mut conn).unwrap_err();
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();

        // We first disable foreign key support. Sqlite currently enables this by default,
        // but this may change in the future. So we disable to check that our enable function
        // works regardless of what Sqlite's default is.
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
        conn.set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, false)
            .unwrap();

        // Enable foreign key support.
        enable_foreign_keys(&conn).unwrap();

        // Create tables with a parent-child foreign key requirement.
        conn.execute_batch(
            r"
                    CREATE TABLE parent(
                        id INTEGER PRIMARY KEY
                    );

                    CREATE TABLE child(
                        id INTEGER PRIMARY KEY,
                        parent_id INTEGER NOT NULL REFERENCES parent(id)
                    );
                ",
        )
        .unwrap();

        // Check that foreign keys are enforced.
        conn.execute("INSERT INTO parent (id) VALUES (2)", [])
            .unwrap();
        conn.execute("INSERT INTO child (id, parent_id) VALUES (0, 2)", [])
            .unwrap();
        conn.execute("INSERT INTO child (id, parent_id) VALUES (1, 1)", [])
            .unwrap_err();
    }
}
