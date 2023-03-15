use std::collections::HashMap;
use std::time::Instant;

use anyhow::Context;
use bitvec::prelude::Msb0;
use bitvec::vec::BitVec;
use clap::Parser;
use pathfinder_merkle_tree::merkle_tree::MerkleTree;
use pathfinder_merkle_tree::PedersenHash;
use stark_hash::Felt;

#[derive(Parser, Debug)]
#[clap(name = "Global Tree Diff")]
#[clap(about = "Diffs the leaves in the global state table", long_about = None)]
struct Cli {
    #[clap(long)]
    /// Path to the database file
    database: std::path::PathBuf,
    #[clap(long)]
    /// Verify diffs by rebuilding tree and verify roots
    verify: bool,
    #[clap(long)]
    /// The block number to stop at.
    stop: Option<u64>,
}

/// This is a tool to explore the global state tree for a given database as a series of key-value diffs.
///
/// Each block's global tree is opened fully to expose all leaves. These are then diff'd against the
/// previous block and the diff is stored as a json file. Since each tree is explored fully for each block
/// this can become quite slow.
///
/// A smarter implementation is possible - for example, by caching counts for each
/// node in the previous tree (to prevent re-exploring unchanged areas of the tree). This is kept as a future
/// improvement.
///
/// The leaf and diff count for each block is also reported via stdout.
fn main() -> anyhow::Result<()> {
    let cli = dbg!(Cli::parse());
    let db_filepath = cli.database;
    let verify = cli.verify;

    let folder = std::path::Path::new(&env!("CARGO_MANIFEST_DIR")).join("global tree diff");
    std::fs::create_dir_all(&folder).context("Creating tree data folder")?;

    let source = rusqlite::Connection::open(&db_filepath).context("Opening database")?;
    let mut source_stmt = source
        .prepare("SELECT root, number FROM starknet_blocks ORDER BY number ASC")
        .context("Preparing statement")?;
    let mut rows = source_stmt
        .query([])
        .context("Querying for block root and number")?;

    let mut old = HashMap::new();

    let mut in_mem_conn =
        rusqlite::Connection::open_in_memory().context("Creating in-memory database")?;
    in_mem_conn
        .execute(
            r"CREATE TABLE tree(
        hash BLOB PRIMARY KEY,
        data BLOB,
        ref_count INTEGER
    )",
            [],
        )
        .context("Creating in-memory tree table")?;
    let mut old_root = Felt::ZERO;

    while let Some(row) = rows.next().context("Next db row")? {
        let t_block = Instant::now();
        let new_root = row.get_ref_unwrap(0).as_blob().context("root as blob")?;
        let new_root = Felt::from_be_slice(new_root).context("db root parsing")?;
        let number = row.get_ref_unwrap(1).as_i64().context("number")?;

        match (number, cli.stop) {
            (number, Some(stop)) if number as u64 > stop => {
                return Ok(());
            }
            _ => {}
        }

        let mut tx_source = rusqlite::Connection::open(&db_filepath).context("Opening database")?;
        let tx = tx_source.transaction().context("Create db transaction")?;

        let tree = MerkleTree::<_, PedersenHash>::load("tree_global", &tx, new_root)
            .context("Loading tree")?;

        let t_explore = Instant::now();
        let mut new = HashMap::new();
        resolve_and_explore_leaves(&tree, new_root, BitVec::new(), &mut new)
            .with_context(|| format!("Exploring block {number}"))?;
        let t_explore = t_explore.elapsed().as_secs_f32();

        let t_diff = Instant::now();
        let old2 = new.clone();
        let diff = diff_hashmaps(old, new);
        old = old2;
        let t_diff = t_diff.elapsed().as_secs_f32();

        let t_block = t_block.elapsed().as_secs_f32();

        println!(
            "{number} <{t_block:.2}s>: {} <{t_explore:.2}s> with diff {} <{t_diff:.2}s>",
            old.len(),
            diff.len()
        );

        let file = std::fs::File::create(folder.join(format!("{number}.json")))
            .context("Creating diff file for {number}")?;

        serde_json::to_writer_pretty(file, &diff).context("{number}: encoding diff")?;

        // verify
        if verify {
            let tx = in_mem_conn
                .transaction()
                .context("Creating transaction for in-mem db")?;
            let mut tree = MerkleTree::<_, PedersenHash>::load("tree_global", &tx, old_root)
                .context("Loading tree")?;

            for (k, v) in diff {
                tree.set(k.view_bits(), v).context("Applying diff")?;
            }

            let diff_root = tree.commit().context("Committing diff")?;
            tx.commit().context("Committing transaction")?;

            anyhow::ensure!(diff_root == new_root, "Root mismatch for {number}");
        }
        old_root = new_root;
    }

    Ok(())
}

fn resolve_and_explore_leaves<T, H>(
    tree: &MerkleTree<T, H>,
    node: Felt,
    path: BitVec<Msb0, u8>,
    leaves: &mut HashMap<Felt, Felt>,
) -> anyhow::Result<()>
where
    H: pathfinder_merkle_tree::Hash,
    T: pathfinder_storage::merkle_tree::NodeStorage,
{
    let node = tree.resolve(node, path.len()).context("Resolving node")?;

    use pathfinder_merkle_tree::merkle_node::Node::*;
    match node {
        Unresolved(_) => anyhow::bail!("Node remains unresolved somehow"),
        Binary(binary) => {
            let left = match *binary.left.borrow() {
                Unresolved(hash) => hash,
                _ => anyhow::bail!("Left child was magically resolved"),
            };

            let right = match *binary.right.borrow() {
                Unresolved(hash) => hash,
                _ => anyhow::bail!("Right child was magically resolved"),
            };

            let mut left_path = path.clone();
            left_path.push(false);
            let mut right_path = path;
            right_path.push(true);

            resolve_and_explore_leaves(tree, left, left_path, leaves)
                .with_context(|| format!("Exploring left child {left}"))?;
            resolve_and_explore_leaves(tree, right, right_path, leaves)
                .with_context(|| format!("Exploring right child {right}"))?
        }
        Edge(edge) => {
            let child = match *edge.child.borrow() {
                Unresolved(hash) => hash,
                _ => anyhow::bail!("Child was magically resolved"),
            };

            let mut child_path = path;
            child_path.extend_from_bitslice(&edge.path);
            resolve_and_explore_leaves(tree, child, child_path, leaves)
                .with_context(|| format!("Exploring child {child}"))?;
        }
        Leaf(value) => {
            let key = Felt::from_bits(&path).context("Converting path to Felt")?;
            if let Some(_exists) = leaves.insert(key, value) {
                anyhow::bail!("Duplicate entry!");
            }
        }
    }

    Ok(())
}

fn diff_hashmaps(mut old: HashMap<Felt, Felt>, new: HashMap<Felt, Felt>) -> HashMap<Felt, Felt> {
    let mut diff = HashMap::new();

    for (k, v) in new {
        match old.remove(&k) {
            // No change, do nothing
            Some(v_old) if v == v_old => {}
            // Value changed or inserted
            _ => {
                if diff.insert(k, v).is_some() {
                    panic!("Sanity check failed - duplicate entry");
                }
            }
        }
    }

    // Since we have removed all new keys from old, the remaining old kv are those that do not
    // exist in new, i.e. keys which were set to zero. Add these as diff.
    for (k, _) in old {
        if diff.insert(k, Felt::ZERO).is_some() {
            panic!("Sanity check failed - duplicate entry");
        }
    }

    diff
}
