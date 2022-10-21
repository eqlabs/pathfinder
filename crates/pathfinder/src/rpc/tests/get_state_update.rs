use crate::core::GlobalRoot;
use crate::rpc::test_setup::Test;
use crate::rpc::v01::types::reply as v01;
use crate::rpc::v01::types::reply::ErrorCode;
use crate::rpc::v02::method::get_state_update::types as v02;
use crate::sequencer;
use crate::starkhash_bytes;
use crate::storage::fixtures::init::with_n_state_updates;
use serde_json::json;

#[tokio::test]
async fn happy_path_and_starkware_errors() {
    // Common setup for all versions
    let v01 = Test::new("starknet_getStateUpdate", line!())
        .with_storage(|tx| with_n_state_updates(tx, 3))
        .map_pending_then_empty(|_, _| {
            std::iter::repeat(sequencer::reply::StateUpdate {
                block_hash: None,
                new_root: GlobalRoot(starkhash_bytes!(b"new")),
                old_root: GlobalRoot(starkhash_bytes!(b"old")),
                state_diff: sequencer::reply::state_update::StateDiff::empty_for_test(),
            })
            .take(2)
        })
        .with_params(json!([
            // Positional
            [{"block_hash":"0x0"}],
            [{"block_hash":"0x1"}],
            [{"block_hash":"0xdead"}],
            [{"block_number":0}],
            [{"block_number":1}],
            [{"block_number":9999}],
            ["latest"],
            // Named
            {"block_id":{"block_hash":"0x0"}},
            {"block_id":{"block_hash":"0x1"}},
            {"block_id":{"block_hash":"0xdead"}},
            {"block_id":{"block_number":0}},
            {"block_id":{"block_number":1}},
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
    v01.map_expected(|in_storage, in_pending| {
        let in_storage = in_storage.collect::<Vec<_>>();
        let in_pending = in_pending
            .map(Into::into)
            .collect::<Vec<v01::StateUpdate>>();
        vec![
            // Positional
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[2].clone()),
            // Named
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[2].clone()),
            // Pending
            Ok(in_pending[0].clone()), // mapped pending
            Ok(in_pending[1].clone()), // mapped pending
            Ok(in_storage[2].clone()), // empty pending, falls back to latest
            Ok(in_storage[2].clone()), // empty pending, falls back to latest
        ]
    })
    .then_expect_internal_err_when_pending_disabled(
        json!([["pending"], {"block_id":"pending"}]),
        "Internal error: Pending data not supported in this configuration",
    )
    .run(vec!["", "/", "/rpc/v0.1"])
    .await;

    // Test v0.2
    v02.map_expected(|in_storage, in_pending| {
        let in_storage = in_storage
            .map(Into::into)
            .collect::<Vec<v02::StateUpdate>>();
        let in_pending = in_pending
            .map(Into::into)
            .collect::<Vec<v02::StateUpdate>>();
        vec![
            // Positional
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[2].clone()),
            // Named
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[0].clone()),
            Ok(in_storage[1].clone()),
            Err(ErrorCode::InvalidBlockId),
            Ok(in_storage[2].clone()),
            // Pending
            Ok(in_pending[0].clone()),      // mapped pending
            Ok(in_pending[1].clone()),      // mapped pending
            Err(ErrorCode::InvalidBlockId), // empty pending, error
            Err(ErrorCode::InvalidBlockId), // empty pending, error
        ]
    })
    .then_expect_internal_err_when_pending_disabled(
        json!([["pending"], {"block_id":"pending"}]),
        "Pending data not supported in this configuration",
    )
    .run(vec!["/rpc/v0.2"])
    .await;
}
