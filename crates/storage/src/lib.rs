//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

mod contract;
mod ethereum;
pub mod merkle_tree;
mod schema;
mod state;
#[cfg(any(feature = "test-utils", test))]
pub mod test_fixtures;
#[cfg(any(feature = "test-utils", test))]
pub mod test_utils;
pub mod types;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use contract::{CasmClassTable, ClassCommitmentLeavesTable, ContractCodeTable};
pub use ethereum::{EthereumBlocksTable, EthereumTransactionsTable};
use rusqlite::functions::FunctionFlags;
pub use state::{
    CanonicalBlocksTable, ContractsStateTable, EventFilterError, L1StateTable, L1TableBlockId,
    RefsTable, StarknetBlock, StarknetBlocksBlockId, StarknetBlocksTable, StarknetEmittedEvent,
    StarknetEventFilter, StarknetEventsTable, StarknetStateUpdatesTable, StarknetTransactionsTable,
    V02KeyFilter, V03KeyFilter,
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
#[derive(Clone, Copy)]
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
        let manager = SqliteConnectionManager::file(&database_path)
            .with_init(move |c| setup_connection(c, journal_mode));
        let pool = Pool::builder().build(manager)?;

        let mut conn = pool.get()?;
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
            let unique_mem_db = format!("file:memdb{count}?mode=memory&cache=shared");
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

fn setup_connection(
    connection: &mut rusqlite::Connection,
    journal_mode: JournalMode,
) -> Result<(), rusqlite::Error> {
    // set journal mode related pragmas
    match journal_mode {
        JournalMode::Rollback => connection.pragma_update(None, "journal_mode", "DELETE")?,
        JournalMode::WAL => {
            connection.pragma_update(None, "journal_mode", "WAL")?;
            // set journal size limit to 1 GB
            connection.pragma_update(
                None,
                "journal_size_limit",
                (1024usize * 1024 * 1024).to_string(),
            )?;
            // According to the documentation NORMAL is a good choice for WAL mode.
            connection.pragma_update(None, "synchronous", "normal")?;
        }
    }

    // enable foreign keys
    connection.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY,
        true,
    )?;

    connection.create_scalar_function(
        "base64_felts_to_index_prefixed_base32_felts",
        1,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        move |ctx| {
            assert_eq!(ctx.len(), 1, "called with unexpected number of arguments");
            let base64_felts = ctx
                .get_raw(0)
                .as_str()
                .map_err(|e| rusqlite::Error::UserFunctionError(e.into()))?;

            Ok(base64_felts_to_index_prefixed_base32_felts(base64_felts))
        },
    )?;

    Ok(())
}

fn base64_felts_to_index_prefixed_base32_felts(base64_felts: &str) -> String {
    let strings = base64_felts
        .split(' ')
        // Convert only the first 256 elements so that the index fits into one u8
        // we will use as a prefix byte.
        .take(crate::StarknetEventsTable::KEY_FILTER_LIMIT)
        .enumerate()
        .map(|(index, key)| {
            let mut buf: [u8; 33] = [0u8; 33];
            buf[0] = index as u8;
            base64::decode_config_slice(key, base64::STANDARD, &mut buf[1..]).unwrap();
            data_encoding::BASE32_NOPAD.encode(&buf)
        })
        .collect::<Vec<_>>();

    strings.join(" ")
}

/// Migrates the database to the latest version. This __MUST__ be called
/// at the beginning of the application.
fn migrate_database(connection: &mut Connection) -> anyhow::Result<()> {
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
        &format!("SELECT {VERSION_KEY} FROM pragma_user_version;"),
        [],
        |row| row.get::<_, usize>(0),
    )?;
    Ok(version)
}

#[cfg(test)]
mod tests {
    use pathfinder_common::felt;
    use stark_hash::Felt;

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
        setup_connection(&mut conn, JournalMode::Rollback).unwrap();
        migrate_database(&mut conn).unwrap();
        let version = schema_version(&conn).unwrap();
        let expected = schema::migrations().len();
        assert_eq!(version, expected);
    }

    #[test]
    fn migration_fails_if_db_is_newer() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        setup_connection(&mut conn, JournalMode::Rollback).unwrap();

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
        conn.set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, true)
            .unwrap();

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

    #[test]
    fn felts_to_index_prefixed_base32_strings() {
        let input: String = [felt!("0x901823"), felt!("0x901823"), felt!("0x901825")]
            .iter()
            .map(|f| base64::encode(f.as_be_bytes()))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(
            super::base64_felts_to_index_prefixed_base32_felts(&input),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAMCG AEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAMCG AIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAMCK".to_owned()
        );
    }

    #[test]
    fn felts_to_index_prefixed_base32_strings_encodes_the_first_256_felts() {
        let input = [Felt::ZERO; 257]
            .iter()
            .map(|f| base64::encode(f.as_be_bytes()))
            .collect::<Vec<_>>()
            .join(" ");
        let output = super::base64_felts_to_index_prefixed_base32_felts(&input);

        assert_eq!(output.split(' ').count(), 256);
    }
}
