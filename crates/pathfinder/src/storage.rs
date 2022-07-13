//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

mod contract;
mod ethereum;
pub(crate) mod merkle_tree;
mod schema;
mod state;

use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;

pub use contract::{ContractCodeTable, ContractsTable};
pub use ethereum::{EthereumBlocksTable, EthereumTransactionsTable};
pub use state::{
    ContractsStateTable, EventFilterError, L1StateTable, L1TableBlockId, RefsTable, StarknetBlock,
    StarknetBlocksBlockId, StarknetBlocksTable, StarknetEmittedEvent, StarknetEventFilter,
    StarknetEventsTable, StarknetTransactionsTable,
};

use anyhow::Context;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

/// Indicates database is non-existant.
const DB_VERSION_EMPTY: u32 = 0;
/// Current database version.
const DB_VERSION_CURRENT: u32 = 14;
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
    database_path: PathBuf,
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
            database_path,
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

    #[cfg(test)]
    /// Convenience function for tests to create an in-memory database.
    /// Equivalent to [Storage::migrate] with an in-memory backed database.
    pub fn in_memory() -> anyhow::Result<Self> {
        // Create a unique database name so that they are not shared between
        // concurrent tests. i.e. Make every in-mem Storage unique.
        lazy_static::lazy_static!(
            static ref COUNT: Mutex<u64> = Mutex::new(0);
        );
        let unique_mem_db = {
            let mut count = COUNT.lock().unwrap();
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

    // Check that the database is not newer than this application knows of.
    anyhow::ensure!(
        version <= DB_VERSION_CURRENT,
        "Database version is newer than this application ({} > {})",
        version,
        DB_VERSION_CURRENT
    );

    // Migrate incrementally, increasing the version by 1 at a time
    for from_version in version..DB_VERSION_CURRENT {
        let transaction = connection
            .transaction()
            .context("Create database transaction")?;
        match from_version {
            DB_VERSION_EMPTY => schema::revision_0001::migrate(&transaction)?,
            1 => schema::revision_0002::migrate(&transaction).context("migrating from 1")?,
            2 => schema::revision_0003::migrate(&transaction).context("migrating from 2")?,
            3 => schema::revision_0004::migrate(&transaction).context("migrating from 3")?,
            4 => schema::revision_0005::migrate(&transaction).context("migrating from 4")?,
            5 => schema::revision_0006::migrate(&transaction).context("migrating from 5")?,
            6 => schema::revision_0007::migrate(&transaction).context("migrating from 6")?,
            7 => schema::revision_0008::migrate(&transaction).context("migrating from 7")?,
            8 => schema::revision_0009::migrate(&transaction).context("migrating from 8")?,
            9 => schema::revision_0010::migrate(&transaction).context("migrating from 9")?,
            10 => schema::revision_0011::migrate(&transaction).context("migrating from 10")?,
            11 => schema::revision_0012::migrate(&transaction).context("migrating from 11")?,
            12 => schema::revision_0013::migrate(&transaction).context("migrating from 12")?,
            13 => schema::revision_0014::migrate(&transaction).context("migrating from 13")?,
            _ => unreachable!("Database version constraint was already checked!"),
        };
        transaction
            .pragma_update(None, VERSION_KEY, from_version + 1)
            .context("Failed to update the schema version number")?;
        transaction
            .commit()
            .context("Commit migration transaction")?;
    }

    Ok(())
}

/// Returns the current schema version of the existing database,
/// or [DB_VERSION_EMPTY] if database does not yet exist.
fn schema_version(connection: &Connection) -> anyhow::Result<u32> {
    // We store the schema version in the Sqlite provided PRAGMA "user_version",
    // which stores an INTEGER and defaults to 0.
    let version = connection.query_row(
        &format!("SELECT {} FROM pragma_user_version;", VERSION_KEY),
        [],
        |row| row.get::<_, u32>(0),
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
    use super::StarknetBlock;

    use crate::{
        core::{
            ContractAddress, EventData, EventKey, GasPrice, GlobalRoot, SequencerAddress,
            StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
            StarknetTransactionHash, StarknetTransactionIndex,
        },
        sequencer::reply::transaction,
    };

    use stark_hash::StarkHash;

    /// Creates a set of consecutive [StarknetBlock]s starting from L2 genesis,
    /// with arbitrary other values.
    pub(crate) fn create_blocks<const N: usize>() -> [StarknetBlock; N] {
        (0..N)
            .map(|i| StarknetBlock {
                number: StarknetBlockNumber::GENESIS + i as u64,
                hash: StarknetBlockHash(StarkHash::from_hex_str(&"a".repeat(i + 3)).unwrap()),
                root: GlobalRoot(StarkHash::from_hex_str(&"f".repeat(i + 3)).unwrap()),
                timestamp: StarknetBlockTimestamp(i as u64 + 500),
                gas_price: GasPrice::from(i as u64),
                sequencer_address: SequencerAddress(StarkHash::from_be_slice(&[i as u8]).unwrap()),
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// Creates a set of test transactions and receipts.
    pub(crate) fn create_transactions_and_receipts<const N: usize>(
    ) -> [(transaction::Transaction, transaction::Receipt); N] {
        let transactions = (0..N).map(|i| transaction::Transaction {
            calldata: None,
            class_hash: None,
            constructor_calldata: None,
            contract_address: Some(ContractAddress(
                StarkHash::from_hex_str(&"2".repeat(i + 3)).unwrap(),
            )),
            contract_address_salt: None,
            entry_point_type: None,
            entry_point_selector: None,
            signature: None,
            transaction_hash: StarknetTransactionHash(
                StarkHash::from_hex_str(&"f".repeat(i + 3)).unwrap(),
            ),
            max_fee: None,
            nonce: None,
            r#type: transaction::Type::InvokeFunction,
            sender_address: None,
            version: None,
        });
        let receipts = (0..N).map(|i| transaction::Receipt {
            actual_fee: None,
            events: vec![transaction::Event {
                from_address: ContractAddress(StarkHash::from_hex_str(&"2".repeat(i + 3)).unwrap()),
                data: vec![EventData(
                    StarkHash::from_hex_str(&"c".repeat(i + 3)).unwrap(),
                )],
                keys: vec![
                    EventKey(StarkHash::from_hex_str(&"d".repeat(i + 3)).unwrap()),
                    EventKey(StarkHash::from_hex_str("deadbeef").unwrap()),
                ],
            }],
            execution_resources: transaction::ExecutionResources {
                builtin_instance_counter:
                    transaction::execution_resources::BuiltinInstanceCounter::Empty(
                        transaction::execution_resources::EmptyBuiltinInstanceCounter {},
                    ),
                n_steps: i as u64 + 987,
                n_memory_holes: i as u64 + 1177,
            },
            l1_to_l2_consumed_message: None,
            l2_to_l1_messages: Vec::new(),
            transaction_hash: StarknetTransactionHash(
                StarkHash::from_hex_str(&"e".repeat(i + 3)).unwrap(),
            ),
            transaction_index: StarknetTransactionIndex(i as u64 + 2311),
        });

        transactions
            .into_iter()
            .zip(receipts)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
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
        assert_eq!(version, DB_VERSION_EMPTY);
    }

    #[test]
    fn full_migration() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        migrate_database(&mut conn).unwrap();
        let version = schema_version(&conn).unwrap();
        assert_eq!(version, DB_VERSION_CURRENT);
    }

    #[test]
    fn migration_fails_if_db_is_newer() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();

        // Force the schema to a newer version
        conn.pragma_update(None, VERSION_KEY, DB_VERSION_CURRENT + 1)
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
