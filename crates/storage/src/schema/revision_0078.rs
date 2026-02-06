use crate::columns::Column;
use crate::{
    TRIE_CLASS_HASH_COLUMN,
    TRIE_CLASS_NODE_COLUMN,
    TRIE_CONTRACT_HASH_COLUMN,
    TRIE_CONTRACT_NODE_COLUMN,
    TRIE_STORAGE_HASH_COLUMN,
    TRIE_STORAGE_NODE_COLUMN,
};

pub(crate) fn migrate(
    tx: &rusqlite::Transaction<'_>,
    rocksdb: &crate::RocksDBInner,
) -> anyhow::Result<()> {
    tracing::info!("Migrating class trie to RocksDB");
    migrate_trie(
        tx,
        "trie_class",
        rocksdb,
        &TRIE_CLASS_HASH_COLUMN,
        &TRIE_CLASS_NODE_COLUMN,
    )?;

    tracing::info!("Migrating contract trie to RocksDB");
    migrate_trie(
        tx,
        "trie_contracts",
        rocksdb,
        &TRIE_CONTRACT_HASH_COLUMN,
        &TRIE_CONTRACT_NODE_COLUMN,
    )?;

    tracing::info!("Migrating storage trie to RocksDB");
    migrate_trie(
        tx,
        "trie_storage",
        rocksdb,
        &TRIE_STORAGE_HASH_COLUMN,
        &TRIE_STORAGE_NODE_COLUMN,
    )?;

    tx.execute_batch(
        "
        DROP TABLE trie_class;
        DROP TABLE trie_contracts;
        DROP TABLE trie_storage;
        ",
    )?;
    Ok(())
}

const BATCH_SIZE: usize = 1000000;

fn migrate_trie(
    sqlite_txn: &rusqlite::Transaction,
    sqlite_table_name: &str,
    rocksdb: &crate::RocksDBInner,
    hash_column: &Column,
    node_column: &Column,
) -> anyhow::Result<()> {
    let mut stmt = sqlite_txn.prepare(&format!(
        "SELECT idx, hash, data FROM {}",
        sqlite_table_name
    ))?;

    let trie_iter = stmt.query_map([], |row| {
        let idx: u64 = row.get(0)?;
        let hash: [u8; 32] = row.get(1)?;
        let data: Vec<u8> = row.get(2)?;
        Ok((idx, hash, data))
    })?;

    let hash_column = rocksdb.get_column(hash_column);
    let node_column = rocksdb.get_column(node_column);

    let mut batch = crate::RocksDBBatch::default();

    for (i, trie_result) in trie_iter.enumerate() {
        let (idx, hash, data) = trie_result?;
        let idx = idx.to_be_bytes();
        batch.put_cf(&hash_column, &idx, &hash);
        batch.put_cf(&node_column, &idx, &data);

        if i % BATCH_SIZE == BATCH_SIZE - 1 {
            rocksdb.rocksdb.write(&batch)?;
            batch = crate::RocksDBBatch::default();
            tracing::info!(
                "Migrated {} entries from table {}",
                i + 1,
                sqlite_table_name
            );
        }
    }

    rocksdb.rocksdb.write(&batch)?;

    tracing::info!(%sqlite_table_name, "Migrated trie from table");

    Ok(())
}
