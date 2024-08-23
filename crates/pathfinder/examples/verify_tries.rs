use std::collections::{BTreeMap, VecDeque};
use std::num::NonZeroU32;

use anyhow::Context;
use pathfinder_storage::params::RowExt;

fn main() -> anyhow::Result<()> {
    let database_path = std::env::args().nth(1).unwrap();
    let storage = pathfinder_storage::StorageBuilder::file(database_path.into())
        .migrate()?
        .create_pool(NonZeroU32::new(1).unwrap())
        .unwrap();
    let mut db = storage
        .connection()
        .context("Opening database connection")?;
    let tx = db.transaction().unwrap();

    let mut stmt = tx.inner().prepare(
        "SELECT MAX(block_number), root_index, contract_address FROM contract_roots GROUP BY \
         contract_address",
    )?;

    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let block_number = row.get_block_number(0)?;
        let root_index = row.get_optional_i64(1)?;
        let contract_address = row.get_contract_address(2)?;

        let root_index = match root_index {
            None => continue,
            Some(index) => u64::try_from(index).unwrap(),
        };

        let mut to_visit = VecDeque::new();
        let mut nodes = BTreeMap::new();
        let mut parents = BTreeMap::new();
        to_visit.push_back(root_index);

        while let Some(node_index) = to_visit.pop_front() {
            let node = tx.contract_trie_node(node_index)?.context(format!(
                "Loading trie node {node_index} for contract {contract_address} at block \
                 {block_number} root index {root_index}" /* "Loading trie node {node_index}" */
            ));

            let node = match node {
                Err(e) => {
                    println!("Failed: {e}");
                    let mut idx = node_index;
                    while let Some(parent) = parents.get(&idx) {
                        idx = *parent;
                        let parent_node = nodes.get(parent).unwrap();
                        println!("Parent {parent} {parent_node:?}");
                    }
                    continue;
                }
                Ok(node) => node,
            };

            match node {
                pathfinder_storage::StoredNode::Binary { left, right } => {
                    parents.insert(left, node_index);
                    to_visit.push_back(left);
                    parents.insert(right, node_index);
                    to_visit.push_back(right);
                }
                pathfinder_storage::StoredNode::Edge { child, .. } => {
                    parents.insert(child, node_index);
                    to_visit.push_back(child);
                }
                pathfinder_storage::StoredNode::LeafBinary => {}
                pathfinder_storage::StoredNode::LeafEdge { .. } => {}
            }

            nodes.insert(node_index, node);
        }
    }

    Ok(())
}
