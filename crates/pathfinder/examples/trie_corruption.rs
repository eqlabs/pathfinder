use std::num::NonZeroU32;
use std::path::PathBuf;

use p2p_proto::event;
use pathfinder_common::BlockNumber;
use pathfinder_lib::state::{l2_reorg, l2_update0, update_starknet_state, StarknetStateUpdate};
use pathfinder_storage::StorageBuilder;
use starknet_api::block_hash::transaction_commitment;

fn get_latest_block(connection: &mut pathfinder_storage::Connection) -> BlockNumber {
    let tx = connection.transaction().unwrap();
    tx.block_id(pathfinder_storage::BlockId::Latest)
        .unwrap()
        .unwrap()
        .0
}

// Ignore unused fields
#[derive(Debug, serde::Deserialize)]
struct BlockAndStateUpdate {
    block: starknet_gateway_types::reply::Block,
    state_update: starknet_gateway_types::reply::StateUpdate,
}

// Ignore unused fields
#[derive(Debug, serde::Deserialize)]
struct BlockAndClassDefs {
    block: BlockAndStateUpdate,
}

fn main() {
    // 1. Load storage at block 116899
    // 2. Reorg to 116888 (actually 116887)
    // 3. Sync to 116910
    eprintln!("Copying db fixture");

    let mut source_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    source_path.push("../../run/testnet-sepolia.sqlite.116899.pruned");

    let db_dir = tempfile::TempDir::new().unwrap();
    let mut db_path = PathBuf::from(db_dir.path());
    db_path.push("testnet-sepolia.sqlite.116899.pruned");

    std::fs::copy(&source_path, &db_path).unwrap();

    eprintln!("Migrating db");

    let storage = StorageBuilder::file(db_path)
        .migrate()
        .unwrap()
        .create_pool(NonZeroU32::new(100).unwrap())
        .unwrap();

    let mut db_conn = storage.connection().unwrap();

    assert_eq!(get_latest_block(&mut db_conn), 116899u64);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    eprintln!("Reorging");

    rt.block_on(l2_reorg(&mut db_conn, BlockNumber::new_or_panic(116888)))
        .unwrap();

    eprintln!("Reorg done");

    assert_eq!(get_latest_block(&mut db_conn), 116887u64);

    // let db_tx = db_conn.transaction().unwrap();

    for i in 116888u64..=116910 {
        eprintln!("Extracting block {i}");

        let mut block_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        block_path.push(format!("../../run/downloaded-sepolia/{i}.json.zst"));

        // Extract, deserialize, apply state update
        let raw = zstd::decode_all(std::io::BufReader::new(
            std::fs::File::open(block_path).unwrap(),
        ))
        .unwrap();

        let BlockAndClassDefs {
            block:
                BlockAndStateUpdate {
                    block,
                    state_update,
                },
        } = serde_json::from_slice::<BlockAndClassDefs>(&raw).unwrap();
        let state_update: pathfinder_common::StateUpdate = state_update.into();
        // let state_update = StarknetStateUpdate {
        //     contract_updates: &state_update.contract_updates,
        //     system_contract_updates: &state_update.system_contract_updates,
        //     declared_sierra_classes: &state_update.declared_sierra_classes,
        // };

        eprintln!("Updating starknet state {i}...");

        let transaction_commitment = block.transaction_commitment;
        let receipt_commitment = block.receipt_commitment.unwrap();
        let event_commitment = block.event_commitment;
        let state_diff_commitment = block.state_diff_commitment.unwrap();

        let mut this_it_conn = storage.connection().unwrap();

        l2_update0(
            &mut this_it_conn,
            block,
            transaction_commitment,
            receipt_commitment,
            event_commitment,
            state_update,
            state_diff_commitment,
            true,
            storage.clone(),
        )
        .unwrap();

        // update_starknet_state(
        //     &db_tx,
        //     state_update,
        //     false,
        //     BlockNumber::new_or_panic(i),
        //     storage.clone(),
        // )
        // .unwrap();

        eprintln!("Updating starknet state {i} done");
    }
}
