use std::{
    collections::{HashMap, HashSet},
    num::NonZeroU32,
    ops::ControlFlow,
};

use anyhow::Context;
use bitvec::{prelude::Msb0, slice::BitSlice, vec::BitVec};
use pathfinder_common::{
    hash::PedersenHash, trie::TrieNode, BlockNumber, ClassHash, ContractAddress, ContractNonce,
    ContractRoot, ContractStateHash, StorageAddress, StorageValue,
};
use pathfinder_merkle_tree::{
    merkle_node::InternalNode,
    tree::{MerkleTree, Visit},
    ContractsStorageTree, StorageCommitmentTree,
};
use pathfinder_storage::{BlockId, JournalMode, Storage, Transaction};
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

    // let mut global_nodes: HashMap<Felt, (BitVec<u8, Msb0>, InternalNode)> = Default::default();

    let starting_block_number = block_number.saturating_sub(50);
    let starting_block_header = tx
        .block_header(BlockNumber::new_or_panic(starting_block_number).into())?
        .context("Getting block header")?;

    let storage_commitment = starting_block_header.storage_commitment;
    let mut storage_commitment_tree = StorageCommitmentTree::load(&tx, storage_commitment)?;

    let mut global_tree_roots: HashMap<BlockNumber, MerkleTree<PedersenHash, 251>> =
        Default::default();

    for block_number in (starting_block_number + 1)..=block_number {
        let state_update = tx
            .state_update(BlockNumber::new_or_panic(block_number).into())?
            .context("Getting state update")?;

        let mut new_contract_state_nodes = 0_usize;

        for (contract, update) in &state_update.contract_updates {
            let (state_hash, contract_state_nodes) = update_contract_state(
                *contract,
                &update.storage,
                update.nonce,
                update.class.as_ref().map(|x| x.class_hash()),
                &storage_commitment_tree,
                &tx,
            )
            .context("Update contract state")?;

            storage_commitment_tree
                .set(*contract, state_hash)
                .context("Updating storage commitment tree")?;

            new_contract_state_nodes += contract_state_nodes.len();
        }

        for (contract, update) in &state_update.system_contract_updates {
            let (state_hash, contract_state_nodes) = update_contract_state(
                *contract,
                &update.storage,
                None,
                None,
                &storage_commitment_tree,
                &tx,
            )
            .context("Update system contract state")?;

            storage_commitment_tree
                .set(*contract, state_hash)
                .context("Updating system contract storage commitment tree")?;

            new_contract_state_nodes += contract_state_nodes.len();
        }

        let (new_storage_commitment, nodes) = storage_commitment_tree
            .commit_mut()
            .context("Apply storage commitment tree updates")?;

        println!(
            "Applied block number {}, storage root {}, new global nodes {}, new contract state nodes {}",
            block_number,
            new_storage_commitment,
            nodes.len(),
            new_contract_state_nodes
        );

        global_tree_roots.insert(
            BlockNumber::new_or_panic(block_number),
            storage_commitment_tree.tree().clone(),
        );

        // let mut visitor_fn = |node: &InternalNode, path: &BitSlice<u8, Msb0>| {
        //     if global_nodes.contains_key(&node.hash().unwrap()) {
        //         return ControlFlow::Continue(Visit::StopSubtree);
        //     }
        //     match node {
        //         InternalNode::Binary(_) | InternalNode::Edge(_) | InternalNode::Leaf(_) => {
        //             global_nodes.insert(node.hash().unwrap(), (path.to_bitvec(), node.clone()));
        //         }
        //         InternalNode::Unresolved(_) => {}
        //     };
        //     ControlFlow::Continue::<(), Visit>(Visit::ContinueDeeper)
        // };

        // tree.dfs(&mut visitor_fn)?;
    }

    // println!("Global tree nodes: {}", global_nodes.len());

    // let mut contract_storage_internal_nodes: HashSet<BitVec<u8, Msb0>> = Default::default();
    // let mut contract_storage_leaves: HashSet<BitVec<u8, Msb0>> = Default::default();

    // for contract_index in progressed::ProgressBar::new(0..contract_states.len())
    //     .set_title("Checking contract state tries")
    // {
    //     let contract_state_hash = contract_states.get(contract_index).unwrap();
    //     let (contract_root, _, _) = tx
    //         .contract_state(*contract_state_hash)?
    //         .context("Getting contract state")?;

    //     let mut tree = ContractsStorageTree::load(&tx, contract_root);

    //     let mut visitor_fn = |node: &InternalNode, path: &BitSlice<u8, Msb0>| {
    //         match node {
    //             InternalNode::Binary(_) | InternalNode::Edge(_) => {
    //                 contract_storage_internal_nodes.insert(path.to_bitvec());
    //             }
    //             InternalNode::Leaf(_) => {
    //                 contract_storage_leaves.insert(path.to_bitvec());
    //             }
    //             InternalNode::Unresolved(_) => {}
    //         };

    //         ControlFlow::Continue::<(), Visit>(Default::default())
    //     };

    //     tree.dfs(&mut visitor_fn)?;
    // }

    // println!(
    //     "Contracts tree: internal {}, leaf {}",
    //     contract_storage_internal_nodes.len(),
    //     contract_storage_leaves.len()
    // );

    Ok(())
}

/// Updates a contract's state with and returns the resulting [ContractStateHash].
pub fn update_contract_state(
    contract_address: ContractAddress,
    updates: &HashMap<StorageAddress, StorageValue>,
    new_nonce: Option<ContractNonce>,
    new_class_hash: Option<ClassHash>,
    storage_commitment_tree: &StorageCommitmentTree<'_>,
    transaction: &Transaction<'_>,
) -> anyhow::Result<(ContractStateHash, HashMap<Felt, TrieNode>)> {
    // Update the contract state tree.
    let state_hash = storage_commitment_tree
        .get(contract_address)
        .context("Get contract state hash from global state tree")?
        .unwrap_or(ContractStateHash(Felt::ZERO));

    // Fetch contract's previous root, class hash and nonce.
    //
    // If the contract state does not exist yet (new contract):
    // Contract root defaults to ZERO because that is the default merkle tree value.
    // Contract nonce defaults to ZERO because that is its historical value before being added in 0.10.
    let (old_root, old_class_hash, old_nonce) = transaction
        .contract_state(state_hash)
        .context("Read contract root and nonce from contracts state table")?
        .map_or_else(
            || (ContractRoot::ZERO, None, ContractNonce::ZERO),
            |(root, class_hash, nonce)| (root, Some(class_hash), nonce),
        );

    let new_nonce = new_nonce.unwrap_or(old_nonce);

    // Load the contract tree and insert the updates.
    let (new_root, nodes) = if !updates.is_empty() {
        let mut contract_tree = ContractsStorageTree::load(transaction, old_root);
        for (key, value) in updates {
            contract_tree
                .set(*key, *value)
                .context("Update contract storage tree")?;
        }
        let (contract_root, nodes) = contract_tree
            .commit()
            .context("Apply contract storage tree changes")?;

        (contract_root, nodes)
    } else {
        (old_root, HashMap::default())
    };

    // Calculate contract state hash, update global state tree and persist pre-image.
    //
    // The contract at address 0x1 is special. It was never deployed and doesn't have a class.
    let class_hash = if contract_address == ContractAddress::ONE {
        ClassHash::ZERO
    } else {
        new_class_hash
            .or(old_class_hash)
            .context("Class hash is unknown for new contract")?
    };
    let contract_state_hash = pathfinder_merkle_tree::contract_state::calculate_contract_state_hash(
        class_hash, new_root, new_nonce,
    );

    // transaction
    //     .insert_contract_state(contract_state_hash, class_hash, new_root, new_nonce)
    //     .context("Insert constract state hash into contracts state table")?;

    Ok((contract_state_hash, nodes))
}
