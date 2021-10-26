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

    pub fn new(mut connection: Connection) -> Result<Self> {
        let mut database = Self { connection };

        // Apply schema migrations.
        let existing_version = database.schema_version()?;
        database.migrate(existing_version)?;

        Ok(database)
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
                    // Todo..
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

    #[test]
    fn schema_version_defaults_to_zero() {
        let connection = Connection::open_in_memory().unwrap();
        let mut db = Storage { connection };
        assert_eq!(db.schema_version().unwrap(), 0);
    }

    #[test]
    fn full_migration() {
        let connection = Connection::open_in_memory().unwrap();
        let mut db = Storage { connection };
        assert!(db.migrate(0).is_ok());
        assert_eq!(db.schema_version().unwrap(), Storage::SCHEMA_VERSION);
    }

    #[test]
    fn migration_should_fail_for_bad_version() {
        let connection = Connection::open_in_memory().unwrap();
        let mut db = Storage { connection };
        assert!(db.migrate(Storage::SCHEMA_VERSION + 1).is_err());
    }
}
