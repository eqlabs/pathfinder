//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

mod contract;
mod ethereum;
pub mod merkle_tree;
mod state;

use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;

pub use contract::{ContractCodeTable, ContractsTable};
pub use ethereum::{EthereumBlocksTable, EthereumTransactionsTable};
pub use state::{ContractsStateTable, GlobalStateRecord, GlobalStateTable};

use anyhow::Context;
use rusqlite::{Connection, Transaction};

/// Indicates database is non-existant.
const DB_VERSION_EMPTY: u32 = 0;
/// Current database version.
const DB_VERSION_CURRENT: u32 = 2;
/// Sqlite key used for the PRAGMA user version.
const VERSION_KEY: &str = "user_version";

/// Used to create [Connection's](Connection) to the pathfinder database.
///
/// Intended usage:
/// - Use [Storage::migrate] to create the app's database.
/// - Pass the [Storage] (or clones thereof) to components which require database access.
/// - Use [Storage::connection] to create connection's to the database, which can in turn
///   be used to interact with the various [tables](self).
#[cfg_attr(not(test), derive(Clone))]
pub struct Storage {
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
        let tx = conn.transaction().context("Create database transaction")?;
        migrate_database(&tx).context("Migrating database")?;
        tx.commit().context("Commiting migration transaction")?;

        #[cfg(not(test))]
        let storage = Storage { database_path };
        #[cfg(test)]
        let storage = Storage {
            database_path,
            _keep_alive: Mutex::new(conn),
        };

        Ok(storage)
    }

    /// Returns a new Sqlite [Connection] to the database.
    pub fn connection(&self) -> anyhow::Result<Connection> {
        Self::open_connection(&self.database_path)
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

    // Migrate incrementally, increasing the version by 1 at a time
    for from_version in version..DB_VERSION_CURRENT {
        match from_version {
            DB_VERSION_EMPTY => migrate_to_1(transaction)?,
            1 => migrate_to_2(transaction)?,
            _ => unreachable!("Database version constraint was already checked!"),
        }
    }

    // Update the pragma schema if necessary
    if version < DB_VERSION_CURRENT {
        transaction
            .pragma_update(None, VERSION_KEY, DB_VERSION_CURRENT)
            .context("Failed to update the schema version number")?;
    }

    Ok(())
}

/// Creates database tables for version 1
fn migrate_to_1(transaction: &Transaction) -> anyhow::Result<()> {
    // Migrate all the tables.
    contract::migrate_from_0_to_1(transaction)
        .context("Failed to migrate StarkNet contract tables to version 1")?;
    ethereum::migrate_from_0_to_1(transaction)
        .context("Failed to migrate Ethereum tables to version 1")?;
    state::migrate_from_0_to_1(transaction)
        .context("Failed to migrate StarkNet state tables to version 1")
}

fn migrate_to_2(tx: &Transaction) -> anyhow::Result<()> {
    use sha3::{Digest, Keccak256};

    // we had a mishap of forking the schema at version 1 so to really support all combinations of
    // schema at version 1 we need to make sure that contracts table still looks like:
    // CREATE TABLE contracts (
    //     address    BLOB PRIMARY KEY,
    //     hash       BLOB NOT NULL,
    //     bytecode   BLOB,
    //     abi        BLOB,
    //     definition BLOB
    // );

    {
        let migrateable = ["address", "hash", "bytecode", "abi", "definition"];
        let no_need = ["address", "hash"];

        let mut actual = Vec::with_capacity(5);

        let mut stmt = tx.prepare("select name from pragma_table_info(\"contracts\")")?;
        let mut rows = stmt.query([])?;

        while let Some(row) = rows.next()? {
            let name = row
                .get_ref_unwrap(0)
                .as_str()
                .expect("pragma_table_info has column name, for strings");
            // these are only borrowable for the lifetime of the row
            actual.push(name.to_owned());
        }

        if actual == no_need {
            return Ok(());
        }

        assert_eq!(
            &migrateable[..],
            &actual,
            "unknown columns for contracts table"
        );
    }

    tx.execute("alter table contracts rename to contracts_v1", [])?;
    tx.execute(
        "create table contract_code (
            hash       BLOB PRIMARY KEY,
            bytecode   BLOB,
            abi        BLOB,
            definition BLOB
        )",
        [],
    )?;

    // set this to true to have the contracts be dumped into files
    let dump_duplicate_contracts = false;

    let mut uniq_contracts = 0u32;
    let todo: u32 = tx
        .query_row(
            "select count(1) from (select definition from contracts_v1 group by definition)",
            [],
            |r| r.get(0),
        )
        .unwrap();

    let mut keccak256 = Keccak256::new();
    let mut output = vec![0u8; 64];

    let started_at = std::time::Instant::now();

    let mut duplicates = 0;

    // main body of this migration is to split cotracts table into two: contracts and
    // contracts_code *while* taking care of bug which had mixed up abi and bytecode columns.
    // the two "faster to access" columns are recreated from the definition.
    {
        let mut stmt = tx.prepare("select distinct definition from contracts_v1")?;
        let mut rows = stmt.query([])?;

        let mut exists = tx.prepare("select 1 from contract_code where hash = ?")?;

        while let Some(r) = rows.next()? {
            let definition = r.get_ref_unwrap(0).as_blob()?;
            let raw_definition = zstd::decode_all(definition)?;
            let (abi, code, hash) =
                crate::state::contract_hash::extract_abi_code_hash(&raw_definition).with_context(
                    || format!("Failed to process {} bytes of definition", definition.len()),
                )?;

            if exists.exists([&hash.to_be_bytes()[..]])? {
                if dump_duplicate_contracts {
                    // exists already, this could be a problem

                    keccak256.update(definition);
                    let cid = <[u8; 32]>::from(keccak256.finalize_reset());

                    hex::encode_to_slice(&cid[..], &mut output[..]).unwrap();

                    let name = std::str::from_utf8(&output[..]).unwrap();

                    let path = format!("duplicate-{:x}-{}.json.zst", hash, name);

                    std::fs::write(path, definition).unwrap();
                }
                duplicates += 1;
            } else {
                crate::storage::ContractCodeTable::insert(
                    tx,
                    crate::core::ContractHash(hash),
                    &abi,
                    &code,
                    &raw_definition,
                )?;
                uniq_contracts += 1;
            }

            let div = 100;
            if uniq_contracts > 0 && uniq_contracts % div == 0 {
                let per_one_from_start = started_at.elapsed() / uniq_contracts;

                println!(
                    "{} more contracts ready, {} to go {:?}, {} duplicates",
                    div,
                    todo - uniq_contracts,
                    (todo - uniq_contracts) * per_one_from_start,
                    duplicates
                );
            }
        }
    }

    println!(
        "{} unique contracts, {} duplicates, {:?}",
        uniq_contracts,
        duplicates,
        started_at.elapsed()
    );

    tx.execute(
        "create table contracts (
            address    BLOB PRIMARY KEY,
            hash       BLOB NOT NULL,

            FOREIGN KEY(hash) REFERENCES contract_code(hash)
        )",
        [],
    )?;

    // this could had been just an alter table to drop the columns + create the fk
    let copied_contracts = tx.execute(
        "insert into contracts (address, hash) select old.address, old.hash from contracts_v1 old",
        [],
    )?;

    println!("{copied_contracts} copied from contracts_v1 to contracts");

    let started_at = std::time::Instant::now();
    tx.execute("drop table contracts_v1", [])?;

    println!("table contracts_v1 dropped in {:?}", started_at.elapsed());

    Ok(())
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
