//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

mod contract;
mod ethereum;
pub mod merkle_tree;
mod state;

use std::path::PathBuf;

pub use contract::ContractsTable;
pub use ethereum::{EthereumBlocksTable, EthereumTransactionsTable};
pub use state::{ContractsStateTable, GlobalStateRecord, GlobalStateTable};

use anyhow::Context;
use rusqlite::{Connection, Transaction};

/// Indicates database is non-existant.
const DB_VERSION_EMPTY: u32 = 0;
/// Current database version.
const DB_VERSION_CURRENT: u32 = DB_VERSION_EMPTY + 1;
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
pub struct Storage {
    database_path: PathBuf,
}

impl Storage {
    /// Performs database schema migration and returns a new [Storage].
    ///
    /// This should be called __once__ at the start of the application,
    /// and passed to the various components which require access to the database.
    ///
    /// May be cloned safely.
    pub fn migrate(database_path: PathBuf) -> anyhow::Result<Self> {
        let storage = Storage { database_path };

        let mut conn = storage.connection().context("Open database connection")?;
        let tx = conn.transaction().context("Create database transaction")?;
        migrate_database(&tx).context("Migrating database")?;
        tx.commit().context("Commiting migration transaction")?;

        Ok(storage)
    }

    /// Returns a new Sqlite [Connection] to the database.
    pub fn connection(&self) -> anyhow::Result<Connection> {
        // TODO: think about flags?
        let conn = Connection::open(&self.database_path)?;
        Ok(conn)
    }

    #[cfg(test)]
    /// Convenience function for tests to create an in-memory database.
    /// Equivalent to [Storage::migrate] with an in-memory backed database.
    pub fn in_memory() -> anyhow::Result<Self> {
        Self::migrate("file::memory:".into())
    }
}

/// Migrates the database to the latest version. This __MUST__ be called
/// at the beginning of the application.
fn migrate_database(transaction: &Transaction) -> anyhow::Result<()> {
    enable_foreign_keys(transaction).context("Failed to enable foreign key support")?;
    let version = schema_version(transaction)?;

    // Check that the database is not newer than this application knows of.
    anyhow::ensure!(
        version <= DB_VERSION_CURRENT,
        "Database version is newer than this application ({} > {})",
        version,
        DB_VERSION_CURRENT
    );

    // Migrate all the tables.
    contract::migrate(transaction, version).context("Failed to migrate contracts table")?;
    ethereum::migrate(transaction, version).context("Failed to migrate Ethereum tables")?;
    state::migrate(transaction, version).context("Failed to migrate StarkNet state tables")?;

    // Update the pragma schema.
    transaction
        .pragma_update(None, VERSION_KEY, DB_VERSION_CURRENT)
        .context("Failed to update the schema version number")
}

/// Returns the current schema version of the existing database,
/// or [DB_VERSION_EMPTY] if database does not yet exist.
fn schema_version(transaction: &Transaction) -> anyhow::Result<u32> {
    // We store the schema version in the Sqlite provided PRAGMA "user_version",
    // which stores an INTEGER and defaults to 0.
    let version = transaction.query_row(
        &format!("SELECT {} FROM pragma_user_version;", VERSION_KEY),
        [],
        |row| row.get::<_, u32>(0),
    )?;
    Ok(version)
}

/// Enables foreign key support for the database.
fn enable_foreign_keys(transaction: &Transaction) -> anyhow::Result<()> {
    use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
    transaction.set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
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
        let transaction = conn.transaction().unwrap();

        migrate_database(&transaction).unwrap();
        let version = schema_version(&transaction).unwrap();

        assert_eq!(version, DB_VERSION_CURRENT);
    }

    #[test]
    fn migration_fails_if_db_is_newer() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        // Force the schema to a newer version
        transaction
            .pragma_update(None, VERSION_KEY, DB_VERSION_CURRENT + 1)
            .unwrap();

        // Migration should fail.
        migrate_database(&transaction).unwrap_err();
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        let transaction = conn.transaction().unwrap();

        // We first disable foreign key support. Sqlite currently enables this by default,
        // but this may change in the future. So we disable to check that our enable function
        // works regardless of what Sqlite's default is.
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
        transaction
            .set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, false)
            .unwrap();

        // Enable foreign key support.
        enable_foreign_keys(&transaction).unwrap();

        // Create tables with a parent-child foreign key requirement.
        transaction
            .execute_batch(
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
        transaction
            .execute("INSERT INTO parent (id) VALUES (2)", [])
            .unwrap();
        transaction
            .execute("INSERT INTO child (id, parent_id) VALUES (0, 2)", [])
            .unwrap();
        transaction
            .execute("INSERT INTO child (id, parent_id) VALUES (1, 1)", [])
            .unwrap_err();
    }
}
