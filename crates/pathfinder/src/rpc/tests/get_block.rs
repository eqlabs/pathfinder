use crate::core::StarknetBlockHash;
use crate::core::StarknetBlockNumber;
use crate::rpc::test_setup::Test;
use crate::rpc::tests::init_storage;
use crate::rpc::v01::types::reply as v01;
use crate::rpc::v01::types::reply::ErrorCode;
use crate::rpc::v02::method::get_block::types as v02;
use crate::sequencer;
use crate::starkhash_bytes;
use serde_json::json;
use stark_hash::StarkHash;

#[tokio::test]
async fn happy_path_and_starkware_errors() {
    let genesis = StarknetBlockHash(starkhash_bytes!(b"genesis"));
    let latest = StarknetBlockHash(starkhash_bytes!(b"latest"));
    let no_parent = StarknetBlockHash(StarkHash::ZERO);
    let genesis_header = (
        Some(genesis),
        Some(StarknetBlockNumber::new_or_panic(0)),
        no_parent,
    );
    let latest_header = (
        Some(latest),
        Some(StarknetBlockNumber::new_or_panic(2)),
        StarknetBlockHash(starkhash_bytes!(b"block 1")),
    );
    let pending_block = sequencer::reply::PendingBlock {
        parent_hash: latest,
        transactions: vec![sequencer::reply::transaction::Transaction::nth_declare(0)],
        ..sequencer::reply::PendingBlock::dummy_for_test()
    };
    let pending_header = (None, None, latest);

    for method in ["starknet_getBlockWithTxHashes", "starknet_getBlockWithTxs"] {
        // Common setup for all versions
        let v01 = Test::new(method, line!())
            .with_storage(|tx| {
                init_storage(tx);
                vec![()]
            })
            .map_pending_then_empty(|_, _| std::iter::repeat(pending_block.clone()).take(2))
            .with_params(json!([
                // Positional
                [{"block_hash":genesis}],
                [{"block_hash":"0xdead"}],
                [{"block_number":0}],
                [{"block_number":9999}],
                ["latest"],
                // Named
                {"block_id":{"block_hash":genesis}},
                {"block_id":{"block_hash":"0xdead"}},
                {"block_id":{"block_number":0}},
                {"block_id":{"block_number":9999}},
                {"block_id":"latest"},
                // Pending
                ["pending"],            // Pops mapped pending data
                {"block_id":"pending"}, // Pops mapped pending data
                ["pending"],            // Pops empty pending data
                {"block_id":"pending"}, // Pops empty pending data
            ]))
            .map_err_to_starkware_error_code();
        let v02 = v01.clone();

        // Test v0.1
        v01.with_expected(vec![
            // Positional
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(latest_header),
            // Named
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(latest_header),
            // Pending
            Ok(pending_header), // mapped pending
            Ok(pending_header), // mapped pending
            Ok(latest_header),  // empty pending, falls back to latest
            Ok(latest_header),  // empty pending, falls back to latest
        ])
        .map_actual(|x: v01::Block| {
            match x.transactions {
                v01::Transactions::Full(_) => assert_eq!(method, "starknet_getBlockWithTxs"),
                v01::Transactions::HashesOnly(_) => {
                    assert_eq!(method, "starknet_getBlockWithTxHashes")
                }
            };
            (x.block_hash, x.block_number, x.parent_hash)
        })
        .then_expect_internal_err_when_pending_disabled(
            json!([["pending"], {"block_id":"pending"}]),
            "Internal error: Pending data not supported in this configuration",
        )
        .run(vec!["", "/", "/rpc/v0.1"])
        .await;

        // Test v0.2
        v02.with_expected(vec![
            // Positional
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(latest_header),
            // Named
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(genesis_header),
            Err(ErrorCode::InvalidBlockId),
            Ok(latest_header),
            // Pending
            Ok(pending_header), // mapped pending
            Ok(pending_header), // mapped pending
            Ok(latest_header),  // empty pending, falls back to latest
            Ok(latest_header),  // empty pending, falls back to latest
        ])
        .map_actual(|x: v02::Block| {
            match x.transactions {
                v02::Transactions::Full(_) => assert_eq!(method, "starknet_getBlockWithTxs"),
                v02::Transactions::HashesOnly(_) => {
                    assert_eq!(method, "starknet_getBlockWithTxHashes")
                }
            };
            (x.block_hash, x.block_number, x.parent_hash)
        })
        .then_expect_internal_err_when_pending_disabled(
            json!([["pending"], {"block_id":"pending"}]),
            "Pending data not supported in this configuration",
        )
        .run(vec!["/rpc/v0.2"])
        .await;
    }
}
