//! Local storage.
//!
//! Currently this consists of a Sqlite backend implementation.

// This is intended for internal use only -- do not make public.
mod prelude;

mod bloom;
pub use bloom::BLOCK_RANGE_LEN;
mod connection;
pub mod fake;
mod params;
mod schema;
pub mod test_utils;

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(feature = "aggregate_bloom")]
use std::sync::Mutex;

use anyhow::Context;
#[cfg(feature = "aggregate_bloom")]
use bloom::AggregateBloom;
pub use bloom::EVENT_KEY_FILTER_LIMIT;
pub use connection::*;
use pathfinder_common::{BlockHash, BlockNumber};
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{OpenFlags, OptionalExtension};

/// Sqlite key used for the PRAGMA user version.
const VERSION_KEY: &str = "user_version";

/// Specifies the [journal mode](https://sqlite.org/pragma.html#pragma_journal_mode)
/// of the [Storage].
#[derive(Clone, Copy, Debug)]
pub enum JournalMode {
    Rollback,
    WAL,
}

/// Identifies a specific starknet block stored in the database.
///
/// Note that this excludes the `Pending` variant since we never store pending
/// data in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockId {
    Latest,
    Number(BlockNumber),
    Hash(BlockHash),
}

impl From<BlockHash> for BlockId {
    fn from(value: BlockHash) -> Self {
        Self::Hash(value)
    }
}

impl From<BlockNumber> for BlockId {
    fn from(value: BlockNumber) -> Self {
        Self::Number(value)
    }
}

impl TryFrom<pathfinder_common::BlockId> for BlockId {
    type Error = &'static str;

    fn try_from(value: pathfinder_common::BlockId) -> Result<Self, Self::Error> {
        match value {
            pathfinder_common::BlockId::Number(x) => Ok(BlockId::Number(x)),
            pathfinder_common::BlockId::Hash(x) => Ok(BlockId::Hash(x)),
            pathfinder_common::BlockId::Latest => Ok(BlockId::Latest),
            pathfinder_common::BlockId::Pending => {
                Err("Pending is invalid within the storage context")
            }
        }
    }
}

/// Used to create [Connection's](Connection) to the pathfinder database.
///
/// Intended usage:
/// - Use [StorageBuilder] to create the app's database.
/// - Pass the [Storage] (or clones thereof) to components which require
///   database access.
/// - Use [Storage::connection] to create connection's to the database, which
///   can in turn be used to interact with the various [tables](self).
#[derive(Clone)]
pub struct Storage(Inner);

#[derive(Clone)]
struct Inner {
    /// Uses [`Arc`] to allow _shallow_ [Storage] cloning
    database_path: Arc<PathBuf>,
    pool: Pool<SqliteConnectionManager>,
    bloom_filter_cache: Arc<bloom::Cache>,
    #[cfg(feature = "aggregate_bloom")]
    running_aggregate: Arc<Mutex<AggregateBloom>>,
    trie_prune_mode: TriePruneMode,
}

pub struct StorageManager {
    database_path: PathBuf,
    journal_mode: JournalMode,
    bloom_filter_cache: Arc<bloom::Cache>,
    #[cfg(feature = "aggregate_bloom")]
    running_aggregate: Arc<Mutex<AggregateBloom>>,
    trie_prune_mode: TriePruneMode,
}

impl std::fmt::Debug for StorageManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageManager")
            .field("database_path", &self.database_path)
            .field("journal_mode", &self.journal_mode)
            .field("trie_prune_mode", &self.trie_prune_mode)
            .finish()
    }
}

impl StorageManager {
    fn create_pool_with_flags(
        &self,
        capacity: NonZeroU32,
        open_flags: OpenFlags,
    ) -> anyhow::Result<Storage> {
        let journal_mode = self.journal_mode;
        let pool_manager = SqliteConnectionManager::file(&self.database_path)
            .with_flags(open_flags)
            .with_init(move |connection| setup_connection(connection, journal_mode));
        let pool = Pool::builder()
            .max_size(capacity.get())
            .build(pool_manager)?;

        Ok(Storage(Inner {
            database_path: Arc::new(self.database_path.clone()),
            pool,
            bloom_filter_cache: self.bloom_filter_cache.clone(),
            #[cfg(feature = "aggregate_bloom")]
            running_aggregate: self.running_aggregate.clone(),
            trie_prune_mode: self.trie_prune_mode,
        }))
    }

    pub fn create_pool(&self, capacity: NonZeroU32) -> anyhow::Result<Storage> {
        self.create_pool_with_flags(capacity, OpenFlags::default())
    }

    pub fn create_read_only_pool(&self, capacity: NonZeroU32) -> anyhow::Result<Storage> {
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        self.create_pool_with_flags(capacity, flags)
    }
}

pub struct StorageBuilder {
    database_path: PathBuf,
    journal_mode: JournalMode,
    bloom_filter_cache_size: usize,
    trie_prune_mode: Option<TriePruneMode>,
}

impl StorageBuilder {
    pub fn file(database_path: PathBuf) -> Self {
        Self {
            database_path,
            journal_mode: JournalMode::WAL,
            bloom_filter_cache_size: 16,
            trie_prune_mode: None,
        }
    }

    pub fn journal_mode(mut self, journal_mode: JournalMode) -> Self {
        self.journal_mode = journal_mode;
        self
    }

    pub fn bloom_filter_cache_size(mut self, bloom_filter_cache_size: usize) -> Self {
        self.bloom_filter_cache_size = bloom_filter_cache_size;
        self
    }

    pub fn trie_prune_mode(mut self, trie_prune_mode: Option<TriePruneMode>) -> Self {
        self.trie_prune_mode = trie_prune_mode;
        self
    }

    /// Convenience function for tests to create an in-memory database.
    pub fn in_memory() -> anyhow::Result<Storage> {
        Self::in_memory_with_trie_pruning(TriePruneMode::Archive)
    }

    /// Convenience function for tests to create an in-memory database with a
    /// specific trie prune mode.
    ///
    /// Note that most of the time we _do_ want to use a pool size of 1. We're
    /// using shared cache mode with our in-memory DB to allow multiple
    /// connections from within the same process. This means that in
    /// contrast to a file-based DB we immediately get locking errors in
    /// case of concurrent writes -- a pool size of one avoids this.
    pub fn in_memory_with_trie_pruning(trie_prune_mode: TriePruneMode) -> anyhow::Result<Storage> {
        Self::in_memory_with_trie_pruning_and_pool_size(
            trie_prune_mode,
            NonZeroU32::new(1).unwrap(),
        )
    }

    /// Convenience function for tests to create an in-memory database with a
    /// specific trie prune mode.
    pub fn in_memory_with_trie_pruning_and_pool_size(
        trie_prune_mode: TriePruneMode,
        pool_size: NonZeroU32,
    ) -> anyhow::Result<Storage> {
        // Create a unique database name so that they are not shared between
        // concurrent tests. i.e. Make every in-mem Storage unique.
        static COUNT: std::sync::Mutex<u64> = std::sync::Mutex::new(0);
        let unique_mem_db = {
            let mut count = COUNT.lock().unwrap();
            // &cache=shared allows other threads to see and access the inmemory database
            let unique_mem_db = format!("file:memdb{count}?mode=memory&cache=shared");
            *count += 1;
            unique_mem_db
        };

        let database_path = PathBuf::from(unique_mem_db);
        // This connection must be held until a pool has been created, since an
        // in-memory database is dropped once all its connections are. This connection
        // therefore holds the database in-place until the pool is established.
        let conn = rusqlite::Connection::open(&database_path)?;

        let mut storage = Self::file(database_path)
            .journal_mode(JournalMode::Rollback)
            .migrate()?;

        if let TriePruneMode::Prune { .. } = trie_prune_mode {
            conn.execute(
                "INSERT INTO storage_flags (flag) VALUES ('prune_tries')",
                [],
            )?;
        }

        storage.trie_prune_mode = trie_prune_mode;
        storage.create_pool(pool_size)
    }

    /// Performs the database schema migration and returns a [storage
    /// manager](StorageManager).
    ///
    /// This should be called __once__ at the start of the application,
    /// and passed to the various components which require access to the
    /// database.
    pub fn migrate(self) -> anyhow::Result<StorageManager> {
        let mut open_flags = OpenFlags::default();
        open_flags.remove(OpenFlags::SQLITE_OPEN_CREATE);
        let (mut connection, is_new_database) =
            rusqlite::Connection::open_with_flags(&self.database_path, open_flags)
                .map_or_else(
                    |e| {
                        if e.sqlite_error_code() == Some(rusqlite::ErrorCode::CannotOpen) {
                            rusqlite::Connection::open(&self.database_path).map(|c| (c, true))
                        } else {
                            Err(e)
                        }
                    },
                    |c| Ok((c, false)),
                )
                .context("Opening DB for migration")?;

        // Migration is done with rollback journal mode. Otherwise dropped tables
        // get copied into the WAL which is prohibitively expensive for large
        // tables.
        setup_journal_mode(&mut connection, JournalMode::Rollback)
            .context("Setting journal mode to rollback")?;
        setup_connection(&mut connection, JournalMode::Rollback)
            .context("Setting up database connection")?;

        migrate_database(&mut connection).context("Migrate database")?;

        // Set the journal mode to the desired value.
        setup_journal_mode(&mut connection, self.journal_mode).context("Setting journal mode")?;

        // Validate that configuration matches database flags.
        let trie_prune_mode = self.determine_trie_prune_mode(&mut connection, is_new_database)?;
        if let TriePruneMode::Prune { num_blocks_kept } = trie_prune_mode {
            tracing::info!(history_kept=%num_blocks_kept, "Merkle trie pruning enabled");
        } else {
            tracing::info!("Merkle trie pruning disabled");
        }

        #[cfg(feature = "aggregate_bloom")]
        let running_aggregate = event::reconstruct_running_aggregate(&connection.transaction()?)
            .context("Reconstructing running aggregate bloom filter")?;

        connection
            .close()
            .map_err(|(_connection, error)| error)
            .context("Closing DB after migration")?;

        Ok(StorageManager {
            database_path: self.database_path,
            journal_mode: self.journal_mode,
            bloom_filter_cache: Arc::new(bloom::Cache::with_size(self.bloom_filter_cache_size)),
            #[cfg(feature = "aggregate_bloom")]
            running_aggregate: Arc::new(Mutex::new(running_aggregate)),
            trie_prune_mode,
        })
    }

    /// - If there is no explicitly requested configuration, assumes the user
    ///   wants to archive. If this doesn't match the database setting, errors.
    /// - If there's an explicitly requested setting: uses it if matches DB
    ///   setting, enables pruning and sets flag in the database. Otherwise
    ///   errors.
    fn determine_trie_prune_mode(
        &self,
        connection: &mut rusqlite::Connection,
        is_new_database: bool,
    ) -> anyhow::Result<TriePruneMode> {
        let prune_flag_is_set = connection
            .query_row(
                "SELECT 1 FROM storage_flags WHERE flag = 'prune_tries'",
                [],
                |_| Ok(()),
            )
            .optional()
            .map(|x| x.is_some())?;

        let trie_prune_mode = self.trie_prune_mode.unwrap_or({
            if is_new_database || prune_flag_is_set {
                TriePruneMode::Prune {
                    num_blocks_kept: 20,
                }
            } else {
                TriePruneMode::Archive
            }
        });

        match trie_prune_mode {
            TriePruneMode::Archive => {
                if prune_flag_is_set {
                    anyhow::bail!(
                        "Cannot disable Merkle trie pruning on a database that was created with \
                         it enabled."
                    )
                }
            }
            TriePruneMode::Prune { num_blocks_kept: _ } => {
                if !is_new_database && !prune_flag_is_set {
                    anyhow::bail!(
                        "Cannot enable Merkle trie pruning on a database that was not created \
                         with it enabled."
                    );
                }

                if is_new_database {
                    connection.execute(
                        "INSERT OR IGNORE INTO storage_flags (flag) VALUES ('prune_tries')",
                        [],
                    )?;
                    tracing::info!("Created new database with Merkle trie pruning enabled.");
                }
            }
        }

        Ok(trie_prune_mode)
    }
}

impl Storage {
    /// Returns a new Sqlite [Connection] to the database.
    pub fn connection(&self) -> anyhow::Result<Connection> {
        let conn = self.0.pool.get()?;
        Ok(Connection::new(
            conn,
            self.0.bloom_filter_cache.clone(),
            #[cfg(feature = "aggregate_bloom")]
            self.0.running_aggregate.clone(),
            self.0.trie_prune_mode,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.0.database_path
    }
}

fn setup_journal_mode(
    connection: &mut rusqlite::Connection,
    journal_mode: JournalMode,
) -> Result<(), rusqlite::Error> {
    // set journal mode related pragmas
    match journal_mode {
        JournalMode::Rollback => connection.pragma_update(None, "journal_mode", "DELETE"),
        JournalMode::WAL => {
            connection.pragma_update(None, "journal_mode", "WAL")?;
            // set journal size limit to 1 GB
            connection.pragma_update(
                None,
                "journal_size_limit",
                (1024usize * 1024 * 1024).to_string(),
            )
        }
    }
}

fn setup_connection(
    connection: &mut rusqlite::Connection,
    journal_mode: JournalMode,
) -> Result<(), rusqlite::Error> {
    // Enable foreign keys.
    connection.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_ENABLE_FKEY,
        true,
    )?;

    // Use a large cache for prepared statements.
    connection.set_prepared_statement_cache_capacity(1000);

    match journal_mode {
        JournalMode::Rollback => {
            // According to the documentation FULL is the recommended setting for rollback
            // mode.
            connection.pragma_update(None, "synchronous", "full")?;
        }
        JournalMode::WAL => {
            // According to the documentation NORMAL is a good choice for WAL mode.
            connection.pragma_update(None, "synchronous", "normal")?;
        }
    };

    Ok(())
}

/// Migrates the database to the latest version. This __MUST__ be called
/// at the beginning of the application.
fn migrate_database(connection: &mut rusqlite::Connection) -> anyhow::Result<()> {
    let mut current_revision = schema_version(connection)?;
    let migrations = schema::migrations();

    // The target version is the number of null migrations which have been replaced
    // by the base schema + the new migrations built on top of that.
    let latest_revision = schema::BASE_SCHEMA_REVISION + migrations.len();

    // Apply the base schema if the database is new.
    if current_revision == 0 {
        let tx = connection
            .transaction()
            .context("Create database transaction")?;
        schema::base_schema(&tx).context("Applying base schema")?;
        tx.pragma_update(None, VERSION_KEY, schema::BASE_SCHEMA_REVISION)
            .context("Failed to update the schema version number")?;
        tx.commit().context("Commit migration transaction")?;

        current_revision = schema::BASE_SCHEMA_REVISION;
    }

    // Skip migration if we already at latest.
    if current_revision == latest_revision {
        tracing::info!(%current_revision, "No database migrations required");
        return Ok(());
    }

    // Check for database version compatibility.
    if current_revision < schema::BASE_SCHEMA_REVISION {
        tracing::error!(
            version=%current_revision,
            limit=%schema::BASE_SCHEMA_REVISION,
            "Database version is too old to migrate"
        );
        anyhow::bail!("Database version {current_revision} too old to migrate");
    }

    if current_revision > latest_revision {
        tracing::error!(
            version=%current_revision,
            limit=%latest_revision,
            "Database version is from a newer than this application expected"
        );
        anyhow::bail!(
            "Database version {current_revision} is newer than this application expected \
             {latest_revision}",
        );
    }

    let amount = latest_revision - current_revision;
    tracing::info!(%current_revision, %latest_revision, migrations=%amount, "Performing database migrations");

    // Sequentially apply each missing migration.
    migrations
        .iter()
        .rev()
        .take(amount)
        .rev()
        .try_for_each(|migration| {
            let mut do_migration = || -> anyhow::Result<()> {
                current_revision += 1;
                let span = tracing::info_span!("db_migration", revision = current_revision);
                let _enter = span.enter();

                let transaction = connection
                    .transaction()
                    .context("Create database transaction")?;
                migration(&transaction)?;
                transaction
                    .pragma_update(None, VERSION_KEY, current_revision)
                    .context("Failed to update the schema version number")?;
                transaction
                    .commit()
                    .context("Commit migration transaction")?;

                Ok(())
            };

            do_migration().with_context(|| format!("Migrating to {current_revision}"))
        })?;

    Ok(())
}

/// Returns the current schema version of the existing database,
/// or `0` if database does not yet exist.
fn schema_version(connection: &rusqlite::Connection) -> anyhow::Result<usize> {
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
        let expected = schema::migrations().len() + schema::BASE_SCHEMA_REVISION;
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

        // We first disable foreign key support. Sqlite currently enables this by
        // default, but this may change in the future. So we disable to check
        // that our enable function works regardless of what Sqlite's default
        // is.
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
    fn rpc_test_db_is_migrated() {
        let (_db_dir, db_path) = rpc_test_db_fixture();

        let database = rusqlite::Connection::open(db_path).unwrap();
        let version = schema_version(&database).unwrap();
        let expected = schema::migrations().len() + schema::BASE_SCHEMA_REVISION;

        assert_eq!(version, expected, "RPC database fixture needs migrating");
    }

    fn rpc_test_db_fixture() -> (tempfile::TempDir, PathBuf) {
        let mut source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        source_path.push("../rpc/fixtures/mainnet.sqlite");

        let db_dir = tempfile::TempDir::new().unwrap();
        let mut db_path = PathBuf::from(db_dir.path());
        db_path.push("mainnet.sqlite");

        std::fs::copy(&source_path, &db_path).unwrap();

        (db_dir, db_path)
    }

    #[test]
    fn enabling_merkle_trie_pruning_fails_without_flag() {
        let (_db_dir, db_path) = rpc_test_db_fixture();

        assert_eq!(
            StorageBuilder::file(db_path)
                .trie_prune_mode(Some(TriePruneMode::Prune {
                    num_blocks_kept: 10
                }))
                .migrate()
                .unwrap_err()
                .to_string(),
            "Cannot enable Merkle trie pruning on a database that was not created with it enabled."
        );
    }

    #[test]
    #[cfg(feature = "aggregate_bloom")]
    fn running_aggregate_reconstructed_after_shutdown() {
        use std::num::NonZeroUsize;
        use std::sync::LazyLock;

        use test_utils::*;

        static MAX_BLOCKS_TO_SCAN: LazyLock<NonZeroUsize> =
            LazyLock::new(|| NonZeroUsize::new(10).unwrap());
        static MAX_BLOOM_FILTERS_TO_LOAD: LazyLock<NonZeroUsize> =
            LazyLock::new(|| NonZeroUsize::new(1000).unwrap());
        #[cfg(feature = "aggregate_bloom")]
        static MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD: LazyLock<NonZeroUsize> =
            LazyLock::new(|| NonZeroUsize::new(3).unwrap());

        let blocks = [0, 1, 2, 3, 4, 5];
        let transactions_per_block = 2;
        let headers = create_blocks(&blocks);
        let transactions_and_receipts =
            create_transactions_and_receipts(blocks.len(), transactions_per_block);
        let emitted_events = extract_events(&headers, &transactions_and_receipts);
        let insert_block_data = |tx: &Transaction<'_>, idx: usize| {
            let header = &headers[idx];

            tx.insert_block_header(header).unwrap();
            tx.insert_transaction_data(
                header.number,
                &transactions_and_receipts
                    [idx * transactions_per_block..(idx + 1) * transactions_per_block]
                    .iter()
                    .cloned()
                    .map(|(tx, receipt, ..)| (tx, receipt))
                    .collect::<Vec<_>>(),
                Some(
                    &transactions_and_receipts
                        [idx * transactions_per_block..(idx + 1) * transactions_per_block]
                        .iter()
                        .cloned()
                        .map(|(_, _, events)| events)
                        .collect::<Vec<_>>(),
                ),
            )
            .unwrap();
        };

        // First run starts here...
        let db = crate::StorageBuilder::in_memory().unwrap();
        let db_path = Arc::clone(&db.0.database_path).to_path_buf();

        // Keep this around so that the in-memory database doesn't get dropped.
        let mut rsqlite_conn = rusqlite::Connection::open(&db_path).unwrap();

        let mut conn = db.connection().unwrap();
        let tx = conn.transaction().unwrap();

        // ...we add two blocks.
        for i in 0..2 {
            insert_block_data(&tx, i);
        }

        let filter = EventFilter {
            keys: vec![
                vec![],
                // Key present in all events as the 2nd key.
                vec![pathfinder_common::macro_prelude::event_key!("0xdeadbeef")],
            ],
            page_size: emitted_events.len(),
            ..Default::default()
        };

        let events_from_aggregate_before = tx
            .events_from_aggregate(
                &filter,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap()
            .events;
        let events_before = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap()
            .events;

        assert_eq!(events_before, events_from_aggregate_before);

        // Pretend like we shut down by dropping these.
        tx.commit().unwrap();
        drop(conn);
        drop(db);

        // Second run starts here (same database)...
        let db = crate::StorageBuilder::file(db_path)
            .journal_mode(JournalMode::Rollback)
            .migrate()
            .unwrap()
            .create_pool(NonZeroU32::new(5).unwrap())
            .unwrap();

        let mut conn = db.connection().unwrap();
        let tx = conn.transaction().unwrap();

        // ...we add the rest of the blocks.
        for i in 2..headers.len() {
            insert_block_data(&tx, i);
        }

        let events_from_aggregate_after = tx
            .events_from_aggregate(
                &filter,
                *MAX_BLOCKS_TO_SCAN,
                *MAX_AGGREGATE_BLOOM_FILTERS_TO_LOAD,
            )
            .unwrap()
            .events;
        let events_after = tx
            .events(&filter, *MAX_BLOCKS_TO_SCAN, *MAX_BLOOM_FILTERS_TO_LOAD)
            .unwrap()
            .events;

        assert_eq!(events_after, events_from_aggregate_after);

        let inserted_aggregate_filter_count = rsqlite_conn
            .transaction()
            .unwrap()
            .prepare("SELECT COUNT(*) FROM starknet_events_filters_aggregate")
            .unwrap()
            .query_row([], |row| row.get::<_, u64>(0))
            .unwrap();

        // We are using only the running aggregate.
        assert!(inserted_aggregate_filter_count == 0);
        assert!(events_from_aggregate_after.len() > events_from_aggregate_before.len());
        // Events added in the first run are present in the running aggregate.
        for e in events_from_aggregate_before {
            assert!(events_from_aggregate_after.contains(&e));
        }
    }
}
