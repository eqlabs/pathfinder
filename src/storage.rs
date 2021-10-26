//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

use anyhow::Result;
use rusqlite::Connection;

pub struct Storage {
    connection: Connection,
}

impl Storage {
    /// Current schema version, used to drive schema migration.
    const SCHEMA_VERSION: u32 = 1;

    /// Creates a [Storage] from a [Sqlite Connection](Connection).
    pub fn new(connection: Connection) -> Result<Self> {
        let mut database = Self { connection };

        database.enable_foreign_keys()?;
        let existing_version = database.schema_version()?;
        database.migrate(existing_version)?;

        Ok(database)
    }

    fn enable_foreign_keys(&mut self) -> Result<()> {
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
        self.connection
            .set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, true)?;
        Ok(())
    }

    /// Returns the current schema version of the existing database,
    /// or 0 if database does not yet exist.
    fn schema_version(&mut self) -> Result<u32> {
        // We store the schema version in the Sqlite provided PRAGMA "user_version",
        // which stores an INTEGER and defaults to 0.
        self.connection
            .query_row("SELECT user_version FROM pragma_user_version;", [], |row| {
                row.get::<_, u32>(0)
            })
            .map_err(|err| {
                anyhow::anyhow!(
                    "Failed to read database schema version: {}",
                    err.to_string()
                )
            })
    }

    /// Updates the database schema to the current version.
    fn migrate(&mut self, from: u32) -> Result<()> {
        if from > Self::SCHEMA_VERSION {
            return Err(anyhow::anyhow!("Unknown database schema version: {}", from));
        }

        // Perform all migrations required from `from` to the current version.
        for version in from..Self::SCHEMA_VERSION {
            // We use a transaction to ensure that a each migration completes
            // fully or not at all. This includes updating the schema version.
            let tx = self.connection.transaction()?;

            match version {
                0 => {
                    tx.execute_batch(r"
                        CREATE TABLE l1_blocks(
                            l1_id INTEGER PRIMARY KEY,
                            hash  BLOB    UNIQUE NOT NULL
                        );

                        CREATE TABLE l2_blocks(
                            l2_id INTEGER PRIMARY KEY,
                            hash  BLOB    UNIQUE NOT NULL,

                            l1_id INTEGER NOT NULL REFERENCES l1_blocks(l1_id) ON DELETE CASCADE
                        );

                        CREATE TABLE transactions(
                            tx_id INTEGER PRIMARY KEY,
                            hash  BLOB UNIQUE NOT NULL,

                            l2_id INTEGER NOT NULL REFERENCES l2_blocks(l2_id) ON DELETE CASCADE
                        );

                        CREATE TABLE contracts(
                            contract_id INTEGER PRIMARY KEY,
                            hash        BLOB UNIQUE NOT NULL,
                            code        BLOB,
                            abi         BLOB,

                            tx_id INTEGER NOT NULL REFERENCES transactions(tx_id) ON DELETE CASCADE
                        );

                        CREATE TABLE variables(
                            variable_id INTEGER PRIMARY KEY,
                            hash        BLOB NOT NULL,

                            contract_id INTEGER REFERENCES contracts(contract_id) ON DELETE CASCADE
                        );

                        CREATE TABLE variable_updates(
                            update_id INTEGER PRIMARY KEY,
                            value     BLOB,

                            variable_id INTEGER NOT NULL REFERENCES variables(variable_id) ON DELETE CASCADE,
                            tx_id       INTEGER NOT NULL REFERENCES transactions(tx_id)    ON DELETE CASCADE
                        );
                    ")?;
                }
                other => {
                    return Err(anyhow::anyhow!(
                        "Unhandled database migration verion: {}",
                        other
                    ))
                }
            }

            // Update the schema version and commit the transaction.
            tx.pragma_update(None, "user_version", version + 1)?;
            tx.commit()?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_storage() -> Storage {
        Storage {
            connection: Connection::open_in_memory().unwrap(),
        }
    }

    #[test]
    fn schema_version_defaults_to_zero() {
        let mut db = mem_storage();
        assert_eq!(db.schema_version().unwrap(), 0);
    }

    #[test]
    fn full_migration() {
        let mut db = mem_storage();
        db.migrate(0).unwrap();
        assert_eq!(db.schema_version().unwrap(), Storage::SCHEMA_VERSION);
    }

    #[test]
    fn migration_should_fail_for_bad_version() {
        let mut db = mem_storage();
        assert!(db.migrate(Storage::SCHEMA_VERSION + 1).is_err());
    }

    #[test]
    fn foreign_keys_are_enforced() {
        let mut db = mem_storage();

        // We first disable foreign key support. Sqlite currently enables this by default,
        // but this may change. So we disable to check that our enable function works
        // regardless of what Sqlite's default is.
        use rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY;
        db.connection
            .set_db_config(SQLITE_DBCONFIG_ENABLE_FKEY, false)
            .unwrap();

        // Enable foreign key support.
        db.enable_foreign_keys().unwrap();

        // Create tables with a parent-child foreign key requirement.
        db.connection
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
        db.connection
            .execute("INSERT INTO parent (id) VALUES (2)", [])
            .unwrap();
        assert!(db
            .connection
            .execute("INSERT INTO child (id, parent_id) VALUES (0, 2)", [])
            .is_ok());
        assert!(db
            .connection
            .execute("INSERT INTO child (id, parent_id) VALUES (1, 1)", [])
            .is_err());
    }
}
