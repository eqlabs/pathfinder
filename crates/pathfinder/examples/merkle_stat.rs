use std::{collections::HashMap, num::NonZeroU32, ops::ControlFlow};

use anyhow::Context;
use bitvec::{prelude::Msb0, slice::BitSlice};
use pathfinder_common::{trie::TrieNode, BlockNumber, ContractStateHash};
use pathfinder_merkle_tree::{
    merkle_node::InternalNode, tree::Visit, ContractsStorageTree, StorageCommitmentTree,
};
use pathfinder_storage::{BlockId, JournalMode, Storage};
use stark_hash::Felt;

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

    println!(
        "Checking block number {}, storage root {}",
        block_number, block_header.storage_commitment
    );

    let mut tree = StorageCommitmentTree::load(&tx, block_header.storage_commitment)?;

    let mut global_nodes: HashMap<Felt, (TrieNode, usize)> = Default::default();
    let mut contract_states = Vec::new();

    let mut visitor_fn = |node: &InternalNode, _path: &BitSlice<u8, Msb0>| {
        match node {
            InternalNode::Binary(node) => {
                let hash = node.hash.unwrap();
                let trie_node = TrieNode::Binary {
                    left: node.left.borrow().hash().unwrap(),
                    right: node.right.borrow().hash().unwrap(),
                };
                global_nodes
                    .entry(hash)
                    .and_modify(|(_node, refcount)| *refcount += 1)
                    .or_insert((trie_node, 1));
            }
            InternalNode::Edge(node) => {
                let hash = node.hash.unwrap();
                let trie_node = TrieNode::Edge {
                    child: node.child.borrow().hash().unwrap(),
                    path: node.path.clone(),
                };
                global_nodes
                    .entry(hash)
                    .and_modify(|(_node, refcount)| *refcount += 1)
                    .or_insert((trie_node, 1));
            }
            InternalNode::Leaf(_) | InternalNode::Unresolved(_) => {}
        };

        if let InternalNode::Leaf(felt) = node {
            contract_states.push(ContractStateHash(*felt));
        }

        ControlFlow::Continue::<(), Visit>(Default::default())
    };

    tree.dfs(&mut visitor_fn)?;

    let r = global_nodes
        .iter()
        .filter_map(|(_key, (_node, refcount))| if *refcount > 1 { Some(*refcount) } else { None })
        .count();

    println!(
        "Global tree nodes: {}, muliple references {}",
        global_nodes.len(),
        r
    );

    let mut contract_storage_nodes: HashMap<Felt, (TrieNode, usize)> = Default::default();

    for contract_index in progressed::ProgressBar::new(0..contract_states.len())
        .set_title("Checking contract state tries")
    {
        let contract_state_hash = contract_states.get(contract_index).unwrap();
        let (contract_root, _, _) = tx
            .contract_state(*contract_state_hash)?
            .context("Getting contract state")?;

        let mut tree = ContractsStorageTree::load(&tx, contract_root);

        let mut visitor_fn = |node: &InternalNode, _path: &BitSlice<u8, Msb0>| {
            match node {
                InternalNode::Binary(node) => {
                    let hash = node.hash.unwrap();
                    let trie_node = TrieNode::Binary {
                        left: node.left.borrow().hash().unwrap(),
                        right: node.right.borrow().hash().unwrap(),
                    };
                    contract_storage_nodes
                        .entry(hash)
                        .and_modify(|(_node, refcount)| *refcount += 1)
                        .or_insert((trie_node, 1));
                }
                InternalNode::Edge(node) => {
                    let hash = node.hash.unwrap();
                    let trie_node = TrieNode::Edge {
                        child: node.child.borrow().hash().unwrap(),
                        path: node.path.clone(),
                    };
                    contract_storage_nodes
                        .entry(hash)
                        .and_modify(|(_node, refcount)| *refcount += 1)
                        .or_insert((trie_node, 1));
                }
                InternalNode::Leaf(_) | InternalNode::Unresolved(_) => {}
            };

            ControlFlow::Continue::<(), Visit>(Default::default())
        };

        tree.dfs(&mut visitor_fn)?;
    }

    let r = contract_storage_nodes
        .iter()
        .filter_map(|(_key, (_node, refcount))| if *refcount > 1 { Some(*refcount) } else { None })
        .count();

    println!(
        "Contracts tree nodes: {}, multiple references {}",
        contract_storage_nodes.len(),
        r
    );

    drop(tx);

    Ok(())
}
