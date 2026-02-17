use anyhow::Context;

use crate::columns::Column;
use crate::{
    CONTRACT_STATE_HASHES_COLUMN,
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

    tracing::info!("Migrating contract state hashes to RocksDB");
    migrate_contract_state_hashes(tx, rocksdb)?;

    tx.execute_batch(
        "
        DROP TABLE trie_class;
        DROP TABLE trie_contracts;
        DROP TABLE trie_storage;
        DROP TABLE contract_state_hashes;
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
        batch.put_cf(&hash_column, idx, hash);
        batch.put_cf(&node_column, idx, &data);

        if i % BATCH_SIZE == BATCH_SIZE - 1 {
            rocksdb.rocksdb.write_without_wal(&batch)?;
            batch = crate::RocksDBBatch::default();
            tracing::info!(
                "Migrated {} entries from table {}",
                i + 1,
                sqlite_table_name
            );
        }
    }

    rocksdb.rocksdb.write_without_wal(&batch)?;

    tracing::info!(%sqlite_table_name, "Migrated trie from table");

    Ok(())
}

fn contract_state_hashes_key(block_number: u64, contract_address: &[u8; 32]) -> [u8; 36] {
    let mut key = [0u8; 36];
    let block_number: u32 = block_number.try_into().expect("block number fits into u32");
    let block_number: u32 = u32::MAX - block_number;

    key[..32].copy_from_slice(contract_address);
    key[32..].copy_from_slice(&block_number.to_be_bytes());
    key
}

fn migrate_contract_state_hashes(
    tx: &rusqlite::Transaction<'_>,
    rocksdb: &crate::RocksDBInner,
) -> anyhow::Result<()> {
    let mut stmt = tx
        .prepare("SELECT block_number, contract_address, state_hash FROM contract_state_hashes")
        .context("Preparing contract state hashes query")?;

    let rows = stmt
        .query_map([], |row| {
            let block_number: u64 = row.get(0)?;
            let contract_address: [u8; 32] = row.get(1)?;
            let state_hash: [u8; 32] = row.get(2)?;
            Ok((block_number, contract_address, state_hash))
        })
        .context("Querying contract state hashes")?;

    let column = rocksdb.get_column(&CONTRACT_STATE_HASHES_COLUMN);
    let mut batch = crate::RocksDBBatch::default();

    for (i, row) in rows.enumerate() {
        let (block_number, contract_address, state_hash) =
            row.context("Reading contract state hash row")?;

        let key = contract_state_hashes_key(block_number, &contract_address);
        batch.put_cf(&column, key, &state_hash);

        if i % BATCH_SIZE == BATCH_SIZE - 1 {
            rocksdb
                .rocksdb
                .write_without_wal(&batch)
                .context("Writing contract state hashes batch to RocksDB")?;
            batch = crate::RocksDBBatch::default();
            tracing::info!("Migrated {} contract state hash entries", i + 1);
        }
    }

    rocksdb
        .rocksdb
        .write_without_wal(&batch)
        .context("Writing final contract state hashes batch to RocksDB")?;
    tracing::info!("Contract state hashes migration complete");

    Ok(())
}
