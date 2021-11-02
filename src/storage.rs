//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

use std::collections::HashSet;

use anyhow::Result;
use rusqlite::{Connection, OptionalExtension};
use web3::types::H256;

/// A Sqlite storage backend.
///
/// todo: elaborate when more established.
pub struct Storage {
    connection: Connection,
}

// Todo: move this someplace more sensible.
#[derive(PartialEq, Eq, Debug, Hash, Clone)]
pub struct Block {
    pub number: u64,
    pub hash: H256,
}

#[derive(PartialEq, Eq, Debug, Hash)]
pub struct Transaction {
    pub number: u64,
    pub hash: H256,
    pub block_number: u64,
}

pub struct ContractDeployed {
    pub block_number: u64,
    pub block_hash: H256,

    pub address: H256,
    pub hash: H256,
    pub call_data: Vec<u8>,
}

pub struct VariableUpdate {
    pub block_number: u64,
    pub block_hash: H256,

    pub contract_address: H256,
    pub variable_address: H256,
    pub value: H256,
}

pub enum StateUpdate {
    Contract(ContractDeployed),
    Variable(VariableUpdate),
}

impl StateUpdate {
    fn block(&self) -> Block {
        match self {
            StateUpdate::Contract(contract) => Block {
                number: contract.block_number,
                hash: contract.block_hash,
            },
            StateUpdate::Variable(variable) => Block {
                number: variable.block_number,
                hash: variable.block_hash,
            },
        }
    }
}

impl From<web3::types::BlockHeader> for Block {
    fn from(block: web3::types::BlockHeader) -> Self {
        Block {
            number: block.number.unwrap().as_u64(),
            hash: block.hash.unwrap(),
        }
    }
}

impl From<web3::types::Block<H256>> for Block {
    fn from(block: web3::types::Block<H256>) -> Self {
        Block {
            number: block.number.unwrap().as_u64(),
            hash: block.hash.unwrap(),
        }
    }
}

impl Storage {
    /// Current schema version, used to drive schema migration.
    const SCHEMA_VERSION: u32 = 1;
    /// Sqlite key used for the PRAGMA user version.
    const VERSION_KEY: &'static str = "user_version";

    /// Creates a [Storage] from a [Sqlite Connection](Connection).
    pub fn new(connection: Connection) -> Result<Self> {
        let mut database = Self { connection };

        database.enable_foreign_keys()?;
        let existing_version = database.schema_version()?;
        database.migrate(existing_version)?;

        Ok(database)
    }

    pub fn latest_block(&self, index: usize) -> anyhow::Result<Option<Block>> {
        let r = self
            .connection
            .query_row(
                &format!(
                    r"SELECT * FROM l1_blocks
                            ORDER BY number DESC
                            LIMIT 1
                            OFFSET {}",
                    index
                ),
                [],
                |row| {
                    let number: u64 = row.get(0).unwrap();

                    let hash: Vec<u8> = row.get(1).unwrap();
                    let hash = H256::from_slice(&hash);

                    let block = Block { number, hash };

                    Ok(block)
                },
            )
            .optional()?;

        Ok(r)
    }

    pub fn insert_updates(&mut self, updates: Vec<StateUpdate>) -> anyhow::Result<()> {
        // These should be committed as a single transaction. All go or no go..
        let tx = self.connection.transaction()?;
        // Order of insertion should match table order of depedence, so
        //      blocks, transactions, and then actual state diffs which should be in order..

        // Pull out all unique blocks and transactions.
        let blocks = updates
            .iter()
            .map(|update| update.block())
            .collect::<HashSet<_>>();

        // Insert the blocks.
        for block in blocks {
            tx.execute(
                "INSERT INTO l1_blocks (number, hash) VALUES (?, ?)",
                rusqlite::params![block.number, block.hash.as_bytes()],
            )?;
        }

        // Insert the updates
        // for update in updates {
        //     match update {
        //         StateUpdate::Contract(contract) => {
        //             tx.execute("INSERT", params)
        //         },
        //         StateUpdate::Variable(variable) => todo!(),
        //     }

        // }

        todo!();
    }

    pub fn insert_block(&self, block: &Block) -> anyhow::Result<()> {
        let hash = block.hash.as_bytes().to_vec();

        self.connection.execute(
            "INSERT INTO l1_blocks (number, hash) VALUES (?,?)",
            rusqlite::params![block.number, hash],
        )?;
        Ok(())
    }

    pub fn purge_all_from_block(&self, number: u64) -> anyhow::Result<()> {
        self.connection
            .execute("DELETE FROM l1_blocks WHERE number >= ?", [number])?;
        Ok(())
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
        let version = self.connection.query_row(
            &format!("SELECT {} FROM pragma_user_version;", Self::VERSION_KEY),
            [],
            |row| row.get::<_, u32>(0),
        )?;
        Ok(version)
    }

    /// Updates the database schema to the current version.
    fn migrate(&mut self, from: u32) -> Result<()> {
        // todo: logs will be important here. Maybe emit a log per schema update,
        //       and one if already up-to-date.
        anyhow::ensure!(
            from <= Self::SCHEMA_VERSION,
            "Unknown database schema version: {}",
            from
        );

        // Perform all migrations required from `from` to the current version.
        for version in from..Self::SCHEMA_VERSION {
            // We use a transaction to ensure that a each migration completes
            // fully or not at all. This includes updating the schema version.
            let tx = self.connection.transaction()?;

            match version {
                0 => {
                    tx.execute_batch(r"
                        CREATE TABLE l1_blocks(
                            number INTEGER PRIMARY KEY,
                            hash   BLOB    UNIQUE NOT NULL
                        );

                        CREATE TABLE l2_blocks(
                            number INTEGER PRIMARY KEY,
                            hash   BLOB    UNIQUE NOT NULL,

                            l1_number INTEGER NOT NULL REFERENCES l1_blocks(number) ON DELETE CASCADE
                        );

                        CREATE TABLE transactions(
                            number INTEGER PRIMARY KEY,
                            hash   BLOB UNIQUE NOT NULL,

                            l2_number INTEGER NOT NULL REFERENCES l2_blocks(number) ON DELETE CASCADE
                        );

                        CREATE TABLE contracts(
                            id   INTEGER PRIMARY KEY,
                            hash BLOB UNIQUE NOT NULL,
                            code BLOB,
                            abi  BLOB,

                            tx_id INTEGER NOT NULL REFERENCES transactions(number) ON DELETE CASCADE
                        );

                        CREATE TABLE variables(
                            key  INTEGER PRIMARY KEY,
                            hash BLOB NOT NULL,

                            contract_id INTEGER REFERENCES contracts(id) ON DELETE CASCADE
                        );

                        CREATE TABLE variable_updates(
                            id    INTEGER PRIMARY KEY,
                            value BLOB,

                            variable_key INTEGER NOT NULL REFERENCES variables(key)       ON DELETE CASCADE,
                            tx_id        INTEGER NOT NULL REFERENCES transactions(number) ON DELETE CASCADE
                        );
                    ")?;
                }
                other => anyhow::bail!("Unhandled database migration version: {}", other),
            }

            // Update the schema version and commit the transaction.
            tx.pragma_update(None, Self::VERSION_KEY, version + 1)?;
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
        db.migrate(Storage::SCHEMA_VERSION + 1).unwrap_err();
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
        db.connection
            .execute("INSERT INTO child (id, parent_id) VALUES (0, 2)", [])
            .unwrap();
        db.connection
            .execute("INSERT INTO child (id, parent_id) VALUES (1, 1)", [])
            .unwrap_err();
    }
}
