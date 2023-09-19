use std::{
    collections::{HashMap, VecDeque},
    num::NonZeroU32,
};

use anyhow::Context;
use bitvec::{prelude::Msb0, vec::BitVec, view::BitView};
use mimalloc::MiMalloc;
use pathfinder_common::{trie::TrieNode, BlockNumber, ContractStateHash};
use pathfinder_merkle_tree::merkle_node::Direction;
use pathfinder_storage::{BlockId, JournalMode, Storage};
use rusqlite::params;
use stark_hash::Felt;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();

    let database_path = std::env::args().nth(1).unwrap();
    let storage = Storage::migrate(database_path.into(), JournalMode::WAL)?
        .create_pool(NonZeroU32::new(2).unwrap())?;
    let mut db = storage
        .connection()
        .context("Opening database connection")?;

    let latest_block = {
        let tx = db.transaction().unwrap();
        let (latest_block, _) = tx.block_id(BlockId::Latest)?.unwrap();
        latest_block.get()
    };

    let block_number = std::env::args()
        .nth(2)
        .map(|s| str::parse(&s).unwrap())
        .unwrap_or(latest_block);

    let tx = db.transaction().unwrap();

    let block_header = tx
        .block_header(BlockNumber::new_or_panic(block_number).into())?
        .context("Getting block header")?;

    tracing::info!(%block_number, storage_commitment=%block_header.storage_commitment, "Checking merkle tries at");

    let class_trie_reader = tx.class_trie_reader();

    let mut class_nodes: HashMap<Felt, (TrieNode, usize)> = Default::default();

    let mut to_visit = VecDeque::new();
    to_visit.push_back((block_header.class_commitment.0, BitVec::new()));
    while let Some((felt, current_path)) = to_visit.pop_front() {
        if current_path.len() == 251 {
            continue;
        }

        let (node, _) = class_nodes
            .entry(felt)
            .and_modify(|(_node, refcount)| *refcount += 1)
            .or_insert_with(|| (class_trie_reader.get(&felt).unwrap().unwrap(), 1));

        match node {
            TrieNode::Binary { left, right } => {
                let mut path_left: BitVec<u8, Msb0> = current_path.clone();
                path_left.push(Direction::Left.into());
                to_visit.push_back((*left, path_left));
                let mut path_right = current_path.clone();
                path_right.push(Direction::Right.into());
                to_visit.push_back((*right, path_right));
            }
            TrieNode::Edge { child, path } => {
                let mut path_edge = current_path.clone();
                path_edge.extend_from_bitslice(path);
                to_visit.push_back((*child, path_edge));
            }
        }
    }
    tracing::info!(num=%class_nodes.len(), "Class tree nodes traversed");

    let storage_trie_reader = tx.storage_trie_reader();

    let mut global_nodes: HashMap<Felt, (TrieNode, usize)> = Default::default();
    let mut contract_state_hashes = Vec::new();

    let mut to_visit = VecDeque::new();
    to_visit.push_back((block_header.storage_commitment.0, BitVec::new()));
    while let Some((felt, current_path)) = to_visit.pop_front() {
        if current_path.len() == 251 {
            contract_state_hashes.push(felt);
            continue;
        }

        let (node, _) = global_nodes
            .entry(felt)
            .and_modify(|(_node, refcount)| *refcount += 1)
            .or_insert_with(|| (storage_trie_reader.get(&felt).unwrap().unwrap(), 1));

        match node {
            TrieNode::Binary { left, right } => {
                let mut path_left: BitVec<u8, Msb0> = current_path.clone();
                path_left.push(Direction::Left.into());
                to_visit.push_back((*left, path_left));
                let mut path_right = current_path.clone();
                path_right.push(Direction::Right.into());
                to_visit.push_back((*right, path_right));
            }
            TrieNode::Edge { child, path } => {
                let mut path_edge = current_path.clone();
                path_edge.extend_from_bitslice(path);
                to_visit.push_back((*child, path_edge));
            }
        }
    }

    tracing::info!(num=%global_nodes.len(), "Global tree nodes traversed");

    let contract_trie_reader = tx.contract_trie_reader();
    let mut contract_storage_nodes: HashMap<Felt, (TrieNode, usize)> = Default::default();

    for contract_index in progressed::ProgressBar::new(0..contract_state_hashes.len())
        .set_title("Checking contract state tries")
    {
        let contract_state_hash = contract_state_hashes.get(contract_index).unwrap();
        let (contract_root, _, _) = tx
            .contract_state(ContractStateHash(*contract_state_hash))?
            .context("Getting contract state")?;

        let mut to_visit = VecDeque::new();
        to_visit.push_back((contract_root.0, BitVec::new()));
        while let Some((felt, current_path)) = to_visit.pop_front() {
            if felt == Felt::ZERO {
                continue;
            }

            if current_path.len() == 251 {
                // leaf node
                continue;
            }

            let (node, _) = contract_storage_nodes
                .entry(felt)
                .and_modify(|(_node, refcount)| *refcount += 1)
                .or_insert_with(|| (contract_trie_reader.get(&felt).unwrap().unwrap(), 1));

            match node {
                TrieNode::Binary { left, right } => {
                    let mut path_left: BitVec<u8, Msb0> = current_path.clone();
                    path_left.push(Direction::Left.into());
                    to_visit.push_back((*left, path_left));
                    let mut path_right = current_path.clone();
                    path_right.push(Direction::Right.into());
                    to_visit.push_back((*right, path_right));
                }
                TrieNode::Edge { child, path } => {
                    let mut path_edge = current_path.clone();
                    path_edge.extend_from_bitslice(path);
                    to_visit.push_back((*child, path_edge));
                }
            }
        }
    }

    tracing::info!(num=%contract_storage_nodes.len(), "Contracts tree nodes traversed");

    drop(tx);

    let tx = db.rusqlite_transaction().unwrap();
    tx.execute_batch(
        r"DROP TABLE IF EXISTS tree_class_new;
        CREATE TABLE IF NOT EXISTS tree_class_new (
        hash        BLOB PRIMARY KEY,
        data        BLOB,
        ref_count   INTEGER
    ) WITHOUT ROWID;",
    )
    .unwrap();

    let mut stmt = tx
        .prepare("INSERT INTO tree_class_new (hash, data, ref_count) VALUES (?, ?, ?)")
        .unwrap();

    for (hash, (node, ref_cnt)) in
        progressed::ProgressBar::new(class_nodes.iter()).set_title("Writing class tree nodes")
    {
        stmt.execute(params![hash.as_be_bytes(), serialize_node(node), ref_cnt])
            .unwrap();
    }

    drop(stmt);

    tx.commit().unwrap();

    tracing::info!("Class tree nodes written");

    let tx = db.rusqlite_transaction().unwrap();
    tx.execute_batch(
        r"DROP TABLE IF EXISTS tree_global_new;
        CREATE TABLE IF NOT EXISTS tree_global_new (
        hash        BLOB PRIMARY KEY,
        data        BLOB,
        ref_count   INTEGER
    ) WITHOUT ROWID;",
    )
    .unwrap();

    let mut stmt = tx
        .prepare("INSERT INTO tree_global_new (hash, data, ref_count) VALUES (?, ?, ?)")
        .unwrap();

    for (hash, (node, ref_cnt)) in
        progressed::ProgressBar::new(global_nodes.iter()).set_title("Writing global tree nodes")
    {
        stmt.execute(params![hash.as_be_bytes(), serialize_node(node), ref_cnt])
            .unwrap();
    }

    drop(stmt);

    tx.commit().unwrap();

    tracing::info!("Global tree nodes written");

    let tx = db.rusqlite_transaction().unwrap();
    tx.execute_batch(
        r"DROP TABLE IF EXISTS tree_contracts_new;
        CREATE TABLE IF NOT EXISTS tree_contracts_new (
        hash        BLOB PRIMARY KEY,
        data        BLOB,
        ref_count   INTEGER
    ) WITHOUT ROWID;",
    )
    .unwrap();

    let mut stmt = tx
        .prepare("INSERT INTO tree_contracts_new (hash, data, ref_count) VALUES (?, ?, ?)")
        .unwrap();

    for (hash, (node, ref_cnt)) in progressed::ProgressBar::new(contract_storage_nodes.iter())
        .set_title("Writing contract tree nodes")
    {
        stmt.execute(params![hash.as_be_bytes(), serialize_node(node), ref_cnt])
            .unwrap();
    }

    drop(stmt);

    tx.commit().unwrap();

    tracing::info!("Contract tree nodes written");

    Ok(())
}

fn serialize_node(node: &TrieNode) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(65);

    match node {
        TrieNode::Binary { left, right } => {
            buffer.extend_from_slice(left.as_be_bytes());
            buffer.extend_from_slice(right.as_be_bytes());
        }
        TrieNode::Edge { child, path } => {
            buffer.extend_from_slice(child.as_be_bytes());
            // Bit path must be written in MSB format. This means that the LSB
            // must be in the last bit position. Since we write a fixed number of
            // bytes (32) but the path length may vary, we have to ensure we are writing
            // to the end of the slice.
            buffer.resize(65, 0);
            buffer[32..][..32].view_bits_mut::<Msb0>()[256 - path.len()..]
                .copy_from_bitslice(&path);

            buffer[64] = path.len() as u8;
        }
    }

    buffer
}
