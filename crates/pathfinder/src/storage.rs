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
    ContractsStateTable, L1StateTable, L1TableBlockId, RefsTable, StarknetBlock,
    StarknetBlocksBlockId, StarknetBlocksTable, StarknetTransactionsTable,
};

use anyhow::Context;
use rusqlite::Connection;
use tracing::info;

/// Indicates database is non-existant.
const DB_VERSION_EMPTY: u32 = 0;
/// Current database version.
const DB_VERSION_CURRENT: u32 = 7;
/// Sqlite key used for the PRAGMA user version.
const VERSION_KEY: &str = "user_version";

/// Used to create [Connection's](Connection) to the pathfinder database.
///
/// Intended usage:
/// - Use [Storage::migrate] to create the app's database.
/// - Pass the [Storage] (or clones thereof) to components which require database access.
/// - Use [Storage::connection] to create connection's to the database, which can in turn
///   be used to interact with the various [tables](self).
#[derive(Clone)]
pub struct Storage(std::sync::Arc<Inner>);

struct Inner {
    database_path: PathBuf,
    /// Required to keep the in-memory variant alive. Sqlite drops in-memory databases
    /// as soon as all living connections are dropped, so we prevent this by storing
    /// a keep-alive connection.
    ///
    /// [Connection] is !Sync so we wrap it in [Mutex] to get sync back.
    #[cfg(test)]
    _keep_alive: Mutex<Connection>,
}

impl Storage {
    /// Performs database schema migration and returns a new [Storage].
    ///
    /// This should be called __once__ at the start of the application,
    /// and passed to the various components which require access to the database.
    ///
    /// May be cloned safely.
    pub fn migrate(database_path: PathBuf) -> anyhow::Result<Self> {
        let mut conn = Self::open_connection(&database_path)?;
        migrate_database(&mut conn).context("Migrate database")?;

        #[cfg(not(test))]
        let inner = Inner { database_path };
        #[cfg(test)]
        let inner = Inner {
            database_path,
            _keep_alive: Mutex::new(conn),
        };

        let storage = Storage(std::sync::Arc::new(inner));

        Ok(storage)
    }

    /// Returns a new Sqlite [Connection] to the database.
    pub fn connection(&self) -> anyhow::Result<Connection> {
        Self::open_connection(&self.0.database_path)
    }

    /// Opens a connection the given database path.
    fn open_connection(database_path: &Path) -> anyhow::Result<Connection> {
        // TODO: think about flags?
        let conn = Connection::open(database_path)?;
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

        Self::migrate(database_path)
    }

    pub fn path(&self) -> &Path {
        &self.0.database_path
    }
}

/// Migrates the database to the latest version. This __MUST__ be called
/// at the beginning of the application.
fn migrate_database(connection: &mut Connection) -> anyhow::Result<()> {
    use schema::PostMigrationAction;

    enable_foreign_keys(connection).context("Failed to enable foreign key support")?;
    let version = schema_version(connection)?;

    // Check that the database is not newer than this application knows of.
    anyhow::ensure!(
        version <= DB_VERSION_CURRENT,
        "Database version is newer than this application ({} > {})",
        version,
        DB_VERSION_CURRENT
    );

    let mut post_action = PostMigrationAction::None;

    // Migrate incrementally, increasing the version by 1 at a time
    for from_version in version..DB_VERSION_CURRENT {
        let transaction = connection
            .transaction()
            .context("Create database transaction")?;
        let action = match from_version {
            DB_VERSION_EMPTY => schema::revision_0001::migrate(&transaction)?,
            1 => schema::revision_0002::migrate(&transaction)?,
            2 => schema::revision_0003::migrate(&transaction)?,
            3 => schema::revision_0004::migrate(&transaction)?,
            4 => schema::revision_0005::migrate(&transaction)?,
            5 => schema::revision_0006::migrate(&transaction)?,
            6 => schema::revision_0007::migrate(&transaction)?,
            _ => unreachable!("Database version constraint was already checked!"),
        };
        // If any migration action requires vacuuming, we should vacuum.
        if action == PostMigrationAction::Vacuum {
            post_action = PostMigrationAction::Vacuum;
        }
        transaction
            .pragma_update(None, VERSION_KEY, from_version + 1)
            .context("Failed to update the schema version number")?;
        transaction
            .commit()
            .context("Commit migration transaction")?;
    }

    match post_action {
        PostMigrationAction::Vacuum => {
            info!("Performing database vacuum. This may take a while.");
            connection
                .execute("VACUUM", [])
                .context("Vacuum database")?;
        }
        PostMigrationAction::None => {}
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
