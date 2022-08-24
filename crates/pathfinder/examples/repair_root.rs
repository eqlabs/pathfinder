use std::ops::ControlFlow;

use pathfinder_lib::{
    core::{
        ContractAddress, ContractRoot, ContractStateHash, GlobalRoot, StarknetBlockHash,
        StarknetBlockNumber,
    },
    state::{merkle_node::Node, merkle_tree::Visit},
};
use stark_hash::StarkHash;

fn main() {
    tracing_subscriber::fmt::init();

    let db = match std::env::args().nth(1).map(|path| {
        pathfinder_lib::storage::Storage::migrate(
            path.into(),
            pathfinder_lib::storage::JournalMode::WAL,
        )
    }) {
        Some(Ok(db)) => db,
        Some(Err(e)) => {
            eprintln!("Failed to open database file: {e:?}");
            std::process::exit(1);
        }
        None => {
            let me = std::env::args()
                .nth(0)
                .unwrap_or_else(|| "repair_root".into());
            eprintln!("USAGE: {me} DBFILE BLOCK_NUMBER ADDRESS");
            eprintln!();
            eprintln!("Assumes that the contract root of the given contract is corrupt, if so, will attempt to repair it.");
            std::process::exit(1);
        }
    };

    let block = std::env::args()
        .nth(2)
        .map(|s| s.as_str().parse::<u64>())
        .unwrap_or_else(|| panic!("Missing BLOCK_NUMBER"))
        .unwrap_or_else(|e| panic!("Invalid BLOCK_NUMBER: {e:?}"));

    let block = StarknetBlockNumber::new(block)
        .unwrap_or_else(|| panic!("BLOCK_NUMBER out of range: {block}"));

    let addr = std::env::args()
        .nth(3)
        .map(|s| StarkHash::from_hex_str(s.as_str()))
        .unwrap_or_else(|| panic!("Missing ADDRESS"))
        .unwrap_or_else(|e| panic!("Invalid ADDRESS: {e:?}"));

    let mut conn = db.connection().unwrap();

    let tx = conn.transaction().unwrap();

    let state_update = tx.query_row("select up.data, b.hash, b.root from starknet_state_updates up join starknet_blocks b on (b.hash = up.block_hash) where b.number = ?", [block], |row| {
        let blob = row.get_ref_unwrap(0).as_blob().unwrap();
        let uncompressed = zstd::decode_all(blob).unwrap();

        // these are just extra checks
        let hash = row.get_unwrap::<_, StarknetBlockHash>(1);
        let root = row.get_unwrap::<_, GlobalRoot>(2);

        let decoded = serde_json::from_slice::<pathfinder_lib::rpc::types::reply::StateUpdate>(&uncompressed).unwrap();

        assert_eq!(Some(hash), decoded.block_hash);
        assert_eq!(root, decoded.new_root);

        Ok(decoded)
    }).unwrap();

    let tree = pathfinder_lib::state::state_tree::GlobalStateTree::load(&tx, state_update.new_root)
        .unwrap();

    let found_contract_state_hash = tree.get(ContractAddress::new(addr).unwrap()).unwrap();

    let current_contract_root = tx
        .query_row(
            "select root from contract_states where state_hash = ?",
            [found_contract_state_hash],
            |row| row.get(0),
        )
        .unwrap();

    {
        // ensure that the current tree actually cannot be fully traversed
        let e = fully_traverse(&tx, current_contract_root).unwrap_err();
        println!("expected failure on traversal: {e:?}");
    }

    let tree = pathfinder_lib::state::merkle_tree::MerkleTree::load(
        "tree_global",
        &tx,
        state_update.old_root.0,
    )
    .unwrap();

    // FIXME: this is only the first step I think we might need to walk back state updates, or do
    // we?
    // FIXME: deployments are currently unsupported, but unsure what kind of problems could there
    // be
    let old_contract_state = ContractStateHash(tree.get(addr.view_bits()).unwrap());

    let old_contract_root = tx
        .query_row(
            "select root from contract_states where state_hash = ?",
            [old_contract_state],
            |row| row.get::<_, ContractRoot>(0),
        )
        .unwrap();

    let mut updated = pathfinder_lib::state::merkle_tree::MerkleTree::load(
        "tree_contracts",
        &tx,
        old_contract_root.0,
    )
    .unwrap();

    println!("applying the partial storage diff on top of the old tree");
    state_update
        .state_diff
        .storage_diffs
        .iter()
        .filter_map(|x| {
            if x.address.get() == &addr {
                Some((x.key, x.value))
            } else {
                None
            }
        })
        // .inspect(|pair| println!("{pair:?}"))
        .try_for_each(|(k, v)| updated.set(k.view_bits(), v.0))
        .unwrap();

    // there is currently now way to verify ... except if the walk down the tree fails currently
    let updated_root = updated.commit().unwrap();

    assert_eq!(
        updated_root, current_contract_root.0,
        "the contract root should not change, but the bad rows should get overwritten"
    );

    println!("verifying no more problems");
    fully_traverse(&tx, current_contract_root).unwrap();
    println!("ok");

    tx.commit().unwrap();
}

fn fully_traverse(
    tx: &rusqlite::Transaction<'_>,
    root: ContractRoot,
) -> anyhow::Result<Option<()>> {
    let tree = pathfinder_lib::state::state_tree::ContractsStateTree::load(&tx, root).unwrap();
    tree.dfs(&mut |_: &_, _: &_| ControlFlow::Continue::<(), _>(Visit::ContinueDeeper))
}
