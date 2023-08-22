use std::{collections::HashSet, num::NonZeroU32, ops::ControlFlow};

use anyhow::Context;
use bitvec::{prelude::Msb0, slice::BitSlice, vec::BitVec};
use pathfinder_common::{BlockNumber, ContractStateHash};
use pathfinder_merkle_tree::{
    merkle_node::InternalNode, tree::Visit, ContractsStorageTree, StorageCommitmentTree,
};
use pathfinder_storage::{BlockId, JournalMode, Storage};

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

    let mut global_internal_node_count = 0_usize;
    let mut contract_states = vec![];

    let mut visitor_fn = |node: &InternalNode, _path: &BitSlice<u8, Msb0>| {
        match node {
            InternalNode::Binary(_) | InternalNode::Edge(_) => global_internal_node_count += 1,
            InternalNode::Leaf(contract_address) => {
                contract_states.push(ContractStateHash(*contract_address))
            }
            InternalNode::Unresolved(_) => {}
        };
        ControlFlow::Continue::<(), Visit>(Default::default())
    };

    tree.dfs(&mut visitor_fn)?;

    println!(
        "Global tree: internal {}, leaf {}",
        global_internal_node_count,
        contract_states.len()
    );

    let mut contract_storage_internal_nodes: HashSet<BitVec<u8, Msb0>> = Default::default();
    let mut contract_storage_leaves: HashSet<BitVec<u8, Msb0>> = Default::default();

    for contract_index in progressed::ProgressBar::new(0..contract_states.len())
        .set_title("Checking contract state tries")
    {
        let contract_state_hash = contract_states.get(contract_index).unwrap();
        let (contract_root, _, _) = tx
            .contract_state(*contract_state_hash)?
            .context("Getting contract state")?;

        let mut tree = ContractsStorageTree::load(&tx, contract_root);

        let mut visitor_fn = |node: &InternalNode, path: &BitSlice<u8, Msb0>| {
            match node {
                InternalNode::Binary(_) | InternalNode::Edge(_) => {
                    contract_storage_internal_nodes.insert(path.to_bitvec());
                }
                InternalNode::Leaf(_) => {
                    contract_storage_leaves.insert(path.to_bitvec());
                }
                InternalNode::Unresolved(_) => {}
            };

            ControlFlow::Continue::<(), Visit>(Default::default())
        };

        tree.dfs(&mut visitor_fn)?;
    }

    println!(
        "Contracts tree: internal {}, leaf {}",
        contract_storage_internal_nodes.len(),
        contract_storage_leaves.len()
    );

    Ok(())
}
