use super::{block_bodies, block_headers, state_diffs};
use assert_matches::assert_matches;
use fake::{Fake, Faker};
use p2p_proto_v0::sync::{
    Direction, GetBlockBodies, GetBlockHeaders, GetStateDiffs, Request, Response,
};
use pathfinder_common::BlockNumber;
use pathfinder_storage::{Storage, Transaction};
use rstest::rstest;

#[test]
fn get_next_block_number() {
    use super::get_next_block_number;

    let genesis = BlockNumber::new_or_panic(0);
    assert_eq!(get_next_block_number(genesis, Direction::Backward), None);
    assert_eq!(
        get_next_block_number(genesis, Direction::Forward),
        Some(BlockNumber::new_or_panic(1))
    );

    assert_eq!(
        get_next_block_number(BlockNumber::new_or_panic(1), Direction::Backward),
        Some(genesis)
    );
    assert_eq!(
        get_next_block_number(BlockNumber::new_or_panic(1), Direction::Forward),
        Some(BlockNumber::new_or_panic(2))
    );
}

fn run_request(
    tx: Transaction<'_>,
    request: p2p_proto_v0::sync::Request,
) -> anyhow::Result<p2p_proto_v0::sync::Response> {
    match request {
        Request::GetBlockHeaders(r) => block_headers(tx, r).map(Response::BlockHeaders),
        Request::GetBlockBodies(r) => block_bodies(tx, r).map(Response::BlockBodies),
        Request::GetStateDiffs(r) => state_diffs(tx, r).map(Response::StateDiffs),
        _ => unimplemented!(),
    }
}

#[rstest]
#[case(Request::GetBlockBodies(GetBlockBodies {
    count: 0,
    ..Faker.fake()
}))]
#[case(Request::GetBlockHeaders(GetBlockHeaders {
    count: 0,
    start_block: Faker.fake::<u64>() >> 1,
    ..Faker.fake()
}))]
#[case(Request::GetStateDiffs(GetStateDiffs {
    count: 0,
    ..Faker.fake()
}))]
fn zero_count_yields_empty_reply(#[case] request: Request) {
    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();
    let response = run_request(tx, request.clone()).unwrap();
    match request {
        Request::GetBlockBodies(_) => {
            assert_matches!(response, Response::BlockBodies(r) => assert!(r.block_bodies.is_empty()));
        }
        Request::GetBlockHeaders(_) => {
            assert_matches!(response, Response::BlockHeaders(r) => assert!(r.headers.is_empty()));
        }
        Request::GetStateDiffs(_) => {
            assert_matches!(response, Response::StateDiffs(r) => assert!(r.block_state_updates.is_empty()));
        }
        _ => panic!("Request and reply type mismatch"),
    };
}

#[test]
fn start_block_larger_than_i64max_yields_error() {
    let request = p2p_proto_v0::sync::GetBlockHeaders {
        start_block: (i64::MAX as u64 + 1),
        ..Faker.fake()
    };

    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();
    assert!(block_headers(tx, request).is_err());
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    /// Fixtures for prop tests
    mod fixtures {
        use pathfinder_storage::{
            fake::{with_n_blocks_and_rng, StorageInitializer},
            Storage,
        };
        pub const MAX_NUM_BLOCKS: u64 = super::super::super::MAX_COUNT_IN_TESTS * 2;
        pub const I64_MAX: u64 = i64::MAX as u64;

        pub fn storage_with_seed(seed: u64, num_blocks: u64) -> (Storage, StorageInitializer) {
            use rand::SeedableRng;
            let storage = Storage::in_memory().unwrap();
            // Explicitly choose RNG to make sure seeded storage is always reproducible
            let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);
            let initializer =
                with_n_blocks_and_rng(&storage, num_blocks.try_into().unwrap(), &mut rng);
            (storage, initializer)
        }
    }

    /// Find overlapping range between the DB and the request
    mod overlapping {
        use super::super::super::MAX_COUNT_IN_TESTS;
        use pathfinder_storage::fake::{StorageInitializer, StorageInitializerItem};

        pub fn forward(
            from_db: StorageInitializer,
            start_block: u64,
            count: u64,
        ) -> impl Iterator<Item = StorageInitializerItem> {
            from_db
                .into_iter()
                .skip(start_block.try_into().unwrap())
                .take(std::cmp::min(count, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }

        pub fn backward(
            mut from_db: StorageInitializer,
            start_block: u64,
            count: u64,
            num_blocks: u64,
        ) -> impl Iterator<Item = StorageInitializerItem> {
            if start_block >= num_blocks {
                // The is no overlapping range but we want to keep the iterator type in this
                // branch type-consistent
                from_db.clear();
            }

            from_db
                .into_iter()
                .take((start_block + 1).try_into().unwrap())
                .rev()
                .take(std::cmp::min(count, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }
    }

    /// Strategies used in tests
    mod strategy {
        use super::fixtures::{I64_MAX, MAX_NUM_BLOCKS};
        use proptest::prelude::*;

        prop_compose! {
            fn reasonable_count()(count in 1..=MAX_NUM_BLOCKS) -> u64 {
                count
            }
        }

        prop_compose! {
            fn crazy_count()(count in MAX_NUM_BLOCKS + 1..) -> u64 {
                count
            }
        }

        pub fn count() -> BoxedStrategy<u64> {
            #[allow(clippy::arc_with_non_send_sync)]
            prop_oneof![
                // Occurance 4:1
                4 => reasonable_count(),
                1 => crazy_count(),
            ]
            .boxed()
        }

        prop_compose! {
            fn disjoint_forward()(start in MAX_NUM_BLOCKS..I64_MAX, count in count()) -> (u64, u64) {
                (start, count)
            }
        }

        prop_compose! {
            fn overlapping_forward()(start in 0..MAX_NUM_BLOCKS, count in count()) -> (u64, u64) {
                (start, count)
            }
        }

        fn any_forward() -> BoxedStrategy<(u64, u64)> {
            #[allow(clippy::arc_with_non_send_sync)]
            prop_oneof![
                // Occurance 4:1
                4 => overlapping_forward(),
                1 => disjoint_forward(),
            ]
            .boxed()
        }

        prop_compose! {
            pub fn forward()(
                (start, count) in any_forward(), storage_seed in any::<u64>(), num_blocks in 0..MAX_NUM_BLOCKS) -> (u64, u64, u64, u64) {
                (start, count, storage_seed, num_blocks)
            }
        }

        fn disjoint_backward() -> BoxedStrategy<(u64, u64)> {
            (MAX_NUM_BLOCKS..I64_MAX)
                .prop_perturb(|start, mut rng| {
                    (
                        start,
                        rng.gen_range(1..=start.saturating_sub(MAX_NUM_BLOCKS - 1)),
                    )
                })
                .boxed()
        }

        prop_compose! {
            fn overlapping_backward()(start in 0..MAX_NUM_BLOCKS, count in 1u64..) -> (u64, u64) {
                (start, count)
            }
        }

        pub fn any_backward() -> BoxedStrategy<(u64, u64)> {
            #[allow(clippy::arc_with_non_send_sync)]
            prop_oneof![
                // Occurance 4:1
                4 => overlapping_backward(),
                1 => disjoint_backward(),
            ]
            .boxed()
        }

        prop_compose! {
            pub fn backward()((start, count) in any_backward(), storage_seed in any::<u64>(), num_blocks in 0..MAX_NUM_BLOCKS) -> (u64, u64, u64, u64) {
                (start, count, storage_seed, num_blocks)
            }
        }
    }

    mod headers {
        use super::super::{block_headers, Direction};
        use super::fixtures::storage_with_seed;
        use super::overlapping;
        use crate::p2p_network::client::v0::conv::header;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn forward((start, count, seed, num_blocks) in super::strategy::forward()) {
                let (storage, from_db) = storage_with_seed(seed, num_blocks);

                let from_db = overlapping::forward(from_db, start, count).map(|(header, _, _)| header).collect::<Vec<_>>();

                let request = p2p_proto_v0::sync::GetBlockHeaders {
                    start_block: start,
                    count,
                    // FIXME unused for now, will likely trigger a failure once it is really used in prod code
                    size_limit: 0,
                    direction: Direction::Forward
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let from_p2p = block_headers(tx, request)
                    .unwrap()
                    .headers
                    .into_iter()
                    .map(header::try_from_p2p).collect::<anyhow::Result<Vec<_>>>().unwrap();

                prop_assert_eq!(from_p2p, from_db)
            }

            #[test]
            fn backward((start, count, seed, num_blocks) in super::strategy::backward()) {
                let (storage, from_db) = storage_with_seed(seed, num_blocks);

                let from_db = overlapping::backward(from_db, start, count, num_blocks).map(|(header, _, _)| header).collect::<Vec<_>>();

                let request = p2p_proto_v0::sync::GetBlockHeaders {
                    start_block: start,
                    count,
                    // FIXME unused for now, will likely trigger a failure once it is really used in prod code
                    size_limit: 0,
                    direction: Direction::Backward
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let from_p2p = block_headers(tx, request)
                    .unwrap()
                    .headers
                    .into_iter()
                    .map(header::try_from_p2p).collect::<anyhow::Result<Vec<_>>>().unwrap();

                prop_assert_eq!(from_p2p, from_db)
            }
        }
    }

    mod bodies {
        use super::super::{block_bodies, Direction};
        use super::fixtures::storage_with_seed;
        use super::overlapping;
        use crate::p2p_network::client::v0::conv::body;
        use pathfinder_common::{TransactionNonce, TransactionVersion};
        use proptest::prelude::*;
        use starknet_gateway_types::reply::transaction as gw;

        // Align with the deserialization workaround to avoid false negative mismatches
        fn invoke_v0_to_l1_handler(tx: gw::Transaction) -> gw::Transaction {
            match tx {
                gw::Transaction::Invoke(gw::InvokeTransaction::V0(tx))
                    if tx.entry_point_type == Some(gw::EntryPointType::L1Handler) =>
                {
                    gw::Transaction::L1Handler(gw::L1HandlerTransaction {
                        contract_address: tx.sender_address,
                        entry_point_selector: tx.entry_point_selector,
                        nonce: TransactionNonce::ZERO,
                        calldata: tx.calldata,
                        transaction_hash: tx.transaction_hash,
                        version: TransactionVersion::ZERO,
                    })
                }
                x => x,
            }
        }

        proptest! {
            #[test]
            fn forward((start, count, seed, num_blocks) in super::strategy::forward()) {
                let (storage, from_db) = storage_with_seed(seed, num_blocks);

                let start_hash = match from_db.get(usize::try_from(start).unwrap()).map(|x| x.0.hash) {
                    Some(h) => h,
                    None => {
                        // Assume default as an invalid hash but make sure it really is
                        prop_assume!(from_db.iter().all(|x| x.0.hash != Default::default()));
                        Default::default()
                    },
                };
                let from_db = overlapping::forward(from_db, start, count).map(|(_, body, _)| body.into_iter().map(|(t, r)| (invoke_v0_to_l1_handler(t), r)).unzip()).collect::<Vec<_>>();

                let request = p2p_proto_v0::sync::GetBlockBodies {
                    start_block: start_hash.0,
                    count,
                    // FIXME unused for now, will likely trigger a failure once it is really used in prod code
                    size_limit: 0,
                    direction: Direction::Forward
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let from_p2p = block_bodies(tx, request)
                    .unwrap()
                    .block_bodies
                    .into_iter()
                    .map(|body| body::try_from_p2p(body).unwrap()).collect::<Vec<_>>();

                prop_assert_eq!(from_p2p, from_db)
            }

            #[test]
            fn backward((start, count, seed, num_blocks) in super::strategy::backward()) {
                let (storage, from_db) = storage_with_seed(seed, num_blocks);
                let start_hash = match from_db.get(usize::try_from(start).unwrap()).map(|x| x.0.hash) {
                    Some(h) => h,
                    None => {
                        // Assume default as an invalid hash but make sure it really is
                        prop_assume!(from_db.iter().all(|x| x.0.hash != Default::default()));
                        Default::default()
                    },
                };

                let from_db = overlapping::backward(from_db, start, count, num_blocks).map(|(_, body, _)| body.into_iter().map(|(t, r)| (invoke_v0_to_l1_handler(t), r)).unzip()).collect::<Vec<_>>();

                let request = p2p_proto_v0::sync::GetBlockBodies {
                    start_block: start_hash.0,
                    count,
                    // FIXME unused for now, will likely trigger a failure once it is really used in prod code
                    size_limit: 0,
                    direction: Direction::Backward
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let from_p2p = block_bodies(tx, request)
                    .unwrap()
                    .block_bodies
                    .into_iter()
                    .map(|body| body::try_from_p2p(body).unwrap()).collect::<Vec<_>>();

                prop_assert_eq!(from_p2p, from_db)
            }
        }
    }

    mod state_diffs {
        use super::super::{state_diffs, Direction};
        use super::fixtures::storage_with_seed;
        use super::overlapping;
        use crate::p2p_network::client::v0::conv::state_update;
        use pathfinder_common::StateUpdate;
        use proptest::prelude::*;
        use std::collections::HashMap;

        proptest! {
            #[test]
            fn forward((start, count, seed, num_blocks) in super::strategy::forward()) {
                let (storage, from_db) = storage_with_seed(seed, num_blocks);
                let start_hash = match from_db.get(usize::try_from(start).unwrap()).map(|x| x.0.hash) {
                    Some(h) => h,
                    None => {
                        // Assume default as an invalid hash but make sure it really is
                        prop_assume!(from_db.iter().all(|x| x.0.hash != Default::default()));
                        Default::default()
                    },
                };
                let from_db = overlapping::forward(from_db, start, count).map(|(_, _, state_update)|
                    (state_update.block_hash.0, state_update)
                ).collect::<HashMap<_, _>>();

                let request = p2p_proto_v0::sync::GetStateDiffs {
                    start_block: start_hash.0,
                    count,
                    // FIXME unused for now, will likely trigger a failure once it is really used in prod code
                    size_limit: 0,
                    direction: Direction::Forward
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let from_p2p = state_diffs(tx, request)
                    .unwrap()
                    .block_state_updates
                    .into_iter()
                    .map(|state_update|
                        (state_update.block_hash, StateUpdate::from(state_update::try_from_p2p(state_update).unwrap()))
                    )
                    .collect::<HashMap<_, _>>();

                prop_assert_eq!(from_p2p, from_db);
            }
        }

        proptest! {
            #[test]
            fn backward((start, count, seed, num_blocks) in super::strategy::backward()) {
                let (storage, from_db) = storage_with_seed(seed, num_blocks);
                let start_hash = match from_db.get(usize::try_from(start).unwrap()).map(|x| x.0.hash) {
                    Some(h) => h,
                    None => {
                        // Assume default as an invalid hash but make sure it really is
                        prop_assume!(from_db.iter().all(|x| x.0.hash != Default::default()));
                        Default::default()
                    },
                };
                let from_db = overlapping::backward(from_db, start, count, num_blocks).map(|(_, _, state_update)|
                    (state_update.block_hash.0, state_update)).collect::<HashMap<_, _>>();

                let request = p2p_proto_v0::sync::GetStateDiffs {
                    start_block: start_hash.0,
                    count,
                    // FIXME unused for now, will likely trigger a failure once it is really used in prod code
                    size_limit: 0,
                    direction: Direction::Backward
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();

                let from_p2p = state_diffs(tx, request)
                    .unwrap()
                    .block_state_updates
                    .into_iter()
                    .map(|state_update| {
                        (state_update.block_hash, StateUpdate::from(state_update::try_from_p2p(state_update).unwrap()))
                    }).collect::<HashMap<_, _>>();

                prop_assert_eq!(from_p2p, from_db)
            }
        }
    }
}

mod classes {
    // TODO once Response::Classes stabilized
}
