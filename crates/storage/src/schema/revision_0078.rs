use anyhow::Context;

use crate::columns::Column;
use crate::params::RowExt;
use crate::{
    StoredNode,
    CONTRACT_STATE_HASHES_COLUMN,
    TRIE_CLASS_COLUMN,
    TRIE_CONTRACT_COLUMN,
    TRIE_STORAGE_COLUMN,
};

pub(crate) fn migrate(
    tx: &rusqlite::Transaction<'_>,
    rocksdb: &crate::RocksDBInner,
) -> anyhow::Result<()> {
    tracing::info!("Migrating class trie to RocksDB");
    migrate_trie(tx, "trie_class", rocksdb, &TRIE_CLASS_COLUMN)?;

    tracing::info!("Migrating storage trie to RocksDB");
    migrate_trie(tx, "trie_storage", rocksdb, &TRIE_STORAGE_COLUMN)?;

    tracing::info!("Migrating contract trie to RocksDB");
    migrate_contract_trie(tx, rocksdb)?;

    tracing::info!("Migrating contract state hashes to RocksDB");
    migrate_contract_state_hashes(tx, rocksdb)?;

    // tx.execute_batch(
    //     "
    //     DROP TABLE trie_class;
    //     DROP TABLE trie_contracts;
    //     DROP TABLE trie_storage;
    //     DROP TABLE contract_state_hashes;
    //     ",
    // )?;
    Ok(())
}

const BATCH_SIZE: usize = 1000000;

fn migrate_trie(
    sqlite_txn: &rusqlite::Transaction,
    sqlite_table_name: &str,
    rocksdb: &crate::RocksDBInner,
    column: &Column,
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

    let column: std::sync::Arc<rust_rocksdb::BoundColumnFamily<'_>> = rocksdb.get_column(column);

    let mut buf = [0u8; 256];
    let mut batch = crate::RocksDBBatch::default();

    for (i, trie_result) in trie_iter.enumerate() {
        let (idx, hash, data) = trie_result?;
        let idx = idx.to_be_bytes();
        buf[..32].copy_from_slice(&hash);
        buf[32..32 + data.len()].copy_from_slice(&data);
        batch.put_cf(&column, idx, &buf[..32 + data.len()]);

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

fn migrate_contract_trie(
    tx: &rusqlite::Transaction<'_>,
    rocksdb: &crate::RocksDBInner,
) -> anyhow::Result<()> {
    let mut stmt = tx.prepare("SELECT idx, hash, data FROM trie_contracts")?;
    let trie_iter = stmt.query_map([], |row| {
        let idx: u64 = row.get(0)?;
        let hash: [u8; 32] = row.get(1)?;
        let data: Vec<u8> = row.get(2)?;
        Ok((idx, hash, data))
    })?;

    let mut packed_arrays = SparsePackedArrays::new();

    for (i, trie_result) in trie_iter.enumerate() {
        let (idx, hash, data) = trie_result?;
        packed_arrays.push(idx, &hash, &data);

        if i % BATCH_SIZE == BATCH_SIZE - 1 {
            tracing::info!("Loaded {} contract trie entries into memory", i + 1);
        }
    }

    tracing::info!(
        "Loaded {} contract trie entries into memory",
        packed_arrays.len()
    );

    let mut stmt = tx.prepare("SELECT contract_address, root_index FROM contract_roots")?;
    let roots_iter = stmt.query_map([], |row| {
        let contract_address: [u8; 32] = row.get(0)?;
        let root_index = row.get_optional_i64(1)?;
        Ok((contract_address, root_index))
    })?;

    let column: std::sync::Arc<rust_rocksdb::BoundColumnFamily<'_>> =
        rocksdb.get_column(&TRIE_CONTRACT_COLUMN);

    let mut output = Vec::new();
    let mut key_buf = [0u8; 40];

    for (i, root_result) in roots_iter.enumerate() {
        let (contract_address, root_index) = root_result?;

        if let Some(root_index) = root_index {
            walk_tree(
                &packed_arrays,
                root_index.try_into().expect("root index fits into u64"),
                &mut output,
            );

            let mut batch = crate::RocksDBBatch::default();

            for node_idx in &output {
                let node_data = packed_arrays
                    .get(*node_idx)
                    .expect("node index should exist in packed arrays");

                contract_trie_key(&contract_address, *node_idx, &mut key_buf);
                batch.put_cf(&column, key_buf, node_data);
            }

            rocksdb.rocksdb.write_without_wal(&batch)?;

            if i % 10000 == 9999 {
                tracing::info!("Migrated {} contract trie roots", i + 1);
            }

            output.clear();
        }
    }

    Ok(())
}

fn walk_tree(packed_arrays: &SparsePackedArrays, node_idx: u64, output: &mut Vec<u64>) {
    const CODEC_CFG: bincode::config::Configuration = bincode::config::standard();

    let node_data = packed_arrays
        .get(node_idx)
        .expect("node index should exist in packed arrays");

    // parse node_data to determine if it's a leaf, extension, or branch node
    // and recursively walk child nodes if necessary
    let (node, _): (StoredSerde, usize) =
        bincode::borrow_decode_from_slice(&node_data[32..], CODEC_CFG)
            .expect("decoding node data should succeed");

    output.push(node_idx);

    match node {
        StoredSerde::Binary { left, right } => {
            walk_tree(packed_arrays, left, output);
            walk_tree(packed_arrays, right, output);
        }
        StoredSerde::Edge { child, .. } => {
            walk_tree(packed_arrays, child, output);
        }
        StoredSerde::LeafBinary | StoredSerde::LeafEdge { .. } => {
            // leaf node, no children to walk
        }
    }
}

#[derive(Clone, Debug, bincode::Encode, bincode::BorrowDecode)]
enum StoredSerde {
    Binary { left: u64, right: u64 },
    Edge { child: u64, path: Vec<u8> },
    LeafBinary,
    LeafEdge { path: Vec<u8> },
}

fn contract_trie_key(prefix: &[u8; 32], storage_idx: u64, buf: &mut [u8; 40]) {
    buf[..32].copy_from_slice(prefix);
    let storage_idx_be_bytes = storage_idx.to_be_bytes();
    buf[32..].copy_from_slice(&storage_idx_be_bytes);
}

pub struct SparsePackedArrays {
    cursor: usize,
    keys: Vec<u64>,      // sorted
    offsets: Vec<usize>, // parallel to keys, + 1 sentinel
    data: Vec<u8>,
}

impl SparsePackedArrays {
    pub fn new() -> Self {
        Self {
            cursor: 0,
            keys: Vec::new(),
            offsets: vec![0],
            data: Vec::new(),
        }
    }

    pub fn push(&mut self, key: u64, hash: &[u8], blob: &[u8]) {
        self.keys.push(key);
        *self.offsets.last_mut().unwrap() = self.cursor;
        self.data.extend_from_slice(hash);
        self.data.extend_from_slice(blob);
        self.cursor += hash.len() + blob.len();
        self.offsets.push(self.cursor); // sentinel
    }

    pub fn get(&self, key: u64) -> Option<&[u8]> {
        let idx = self.keys.binary_search(&key).ok()?;
        let start = self.offsets[idx] as usize;
        let end = self.offsets[idx + 1] as usize;
        Some(&self.data[start..end])
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
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
