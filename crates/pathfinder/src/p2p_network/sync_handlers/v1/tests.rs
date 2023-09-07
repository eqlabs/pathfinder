use crate::p2p_network::sync_handlers::v1::{get_bodies, get_headers};
use assert_matches::assert_matches;
use fake::{Fake, Faker};
use p2p_proto_v1::block::{Direction, GetBlockBodies, GetBlockHeaders, Iteration, Step};
use p2p_proto_v1::common::BlockId;
use pathfinder_common::BlockNumber;
use pathfinder_storage::Storage;
use rstest::rstest;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

const I64_MAX: u64 = i64::MAX as u64;

#[rstest]
#[case(0, 1, Direction::Forward, Some(1))]
#[case(0, I64_MAX, Direction::Forward, Some(I64_MAX))]
#[case(1, I64_MAX, Direction::Forward, None)]
#[case(0, 1, Direction::Backward, None)]
#[case(1, 1, Direction::Backward, Some(0))]
#[case(I64_MAX, 1, Direction::Backward, Some(I64_MAX - 1))]
#[case(I64_MAX, I64_MAX, Direction::Backward, Some(0))]
#[case(I64_MAX, I64_MAX + 1, Direction::Backward, None)]
#[test]
fn get_next_block_number(
    #[case] start: u64,
    #[case] step: u64,
    #[case] direction: Direction,
    #[case] expected: Option<u64>,
) {
    assert_eq!(
        super::get_next_block_number(
            BlockNumber::new_or_panic(start),
            Step::from(Some(step)),
            direction
        ),
        expected.map(BlockNumber::new_or_panic)
    );
}

mod empty_reply {
    use super::*;
    #[rustfmt::skip] fn zero_limit() -> Iteration { Iteration { limit: 0, ..Faker.fake() } }
    #[rustfmt::skip] fn invalid_start() -> Iteration { Iteration { start: BlockId(I64_MAX + 1), ..Faker.fake() } }

    #[rstest]
    #[case(GetBlockHeaders {iteration: zero_limit()})]
    #[case(GetBlockHeaders {iteration: invalid_start()})]
    #[tokio::test]
    async fn headers(#[case] request: GetBlockHeaders) {
        let storage = Storage::in_memory().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        // Clone the sender to make sure that the channel is not prematurely closed
        get_headers(&storage, request, tx.clone()).await.unwrap();
        // No reply should be sent
        assert_matches!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[rstest]
    #[case(GetBlockBodies {iteration: zero_limit()})]
    #[case(GetBlockBodies {iteration: invalid_start()})]
    #[tokio::test]
    async fn bodies(#[case] request: GetBlockBodies) {
        let storage = Storage::in_memory().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        // Clone the sender to make sure that the channel is not prematurely closed
        get_bodies(&storage, request, tx.clone()).await.unwrap();
        // No reply should be sent
        assert_matches!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    /// Fixtures for prop tests
    mod fixtures {
        use crate::p2p_network::sync_handlers::v1::MAX_COUNT_IN_TESTS;
        use pathfinder_storage::fake::{with_n_blocks_and_rng, StorageInitializer};
        use pathfinder_storage::Storage;

        pub const MAX_NUM_BLOCKS: u64 = MAX_COUNT_IN_TESTS * 2;

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
        use crate::p2p_network::sync_handlers::v1::MAX_COUNT_IN_TESTS;
        use p2p_proto_v1::block::Step;
        use pathfinder_storage::fake::{StorageInitializer, StorageInitializerItem};

        pub fn forward(
            from_db: StorageInitializer,
            start_block: u64,
            limit: u64,
            step: Step,
        ) -> impl Iterator<Item = StorageInitializerItem> {
            from_db
                .into_iter()
                .skip(start_block.try_into().unwrap())
                .step_by(step.take_inner().try_into().unwrap())
                .take(std::cmp::min(limit, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }
    }

    /// Strategies used in tests
    mod strategy {
        use super::fixtures::MAX_NUM_BLOCKS;
        use p2p_proto_v1::block::Step;
        use proptest::prelude::*;
        use std::ops::Range;

        prop_compose! {
            fn inside(range: Range<u64>)(x in range) -> u64 { x }
        }

        prop_compose! {
            fn outside(range: Range<u64>)(x in range.end..) -> u64 { x }
        }

        pub fn rarely_outside(range: std::ops::Range<u64>) -> BoxedStrategy<u64> {
            // Empty range will trigger a panic in rand::distributions::Uniform
            if range.is_empty() {
                return Just(range.start).boxed();
            }

            prop_oneof![
                // Occurance 4:1
                4 => inside(range.clone()),
                1 => outside(range),
            ]
            .boxed()
        }

        prop_compose! {
            pub fn forward()
                (num_blocks in 0..MAX_NUM_BLOCKS)
                (
                    num_blocks in Just(num_blocks),
                    storage_seed in any::<u64>(),
                    start in rarely_outside(0..num_blocks),
                    // limit of 0 is handled by a separate test
                    limit in rarely_outside(1..num_blocks),
                    // step is always >= 1
                    step in rarely_outside(1..num_blocks / 4),
                ) -> (u64, u64, u64, u64, Step) {
                (num_blocks, storage_seed, start, limit, step.into())
            }
        }
    }

    mod get_headers {
        use super::fixtures::storage_with_seed;
        use super::overlapping;
        use crate::p2p_network::sync_handlers::v1::conv::ToProto;
        use crate::p2p_network::sync_handlers::v1::headers;
        use p2p_proto_v1::block::{
            BlockHeadersResponsePart, Direction, GetBlockHeaders, Iteration,
        };
        use p2p_proto_v1::common::BlockId;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn forward((num_blocks, seed, start, limit, step) in super::strategy::forward()) {
                eprintln!("num_blocks: {num_blocks} start: {start} limit: {limit} step: {step} seed: {seed}");
                let (storage, from_db) = storage_with_seed(seed, num_blocks);
                let from_db = overlapping::forward(from_db, start, limit, step).map(|(header, _, _)| header).collect::<Vec<_>>();

                let request = GetBlockHeaders {
                    iteration: Iteration {
                        start: BlockId(start),
                        limit,
                        step,
                        direction: Direction::Forward,
                    }
                };

                let mut connection = storage.connection().unwrap();
                let tx = connection.transaction().unwrap();
                let reply_vec = headers(tx, request).unwrap();
                let reply_vec = reply_vec.into_iter().map(|reply | match reply.block_part {
                    BlockHeadersResponsePart::Header(x) => *x,
                    _ => panic!("Wrong reply type"),
                }).collect::<Vec<_>>();

                prop_assert_eq!(reply_vec.len(), from_db.len());

                // let reply_vec_cloned = reply_vec.clone();
                // let from_db_cloned = from_db.clone();

                // TODO remove this assertion
                // This is wrong but just temporary, we should do the converse here - transform the reply into out storage format
                let from_db = from_db.into_iter().map(ToProto::to_proto).collect::<Vec<_>>();
                prop_assert_eq!(reply_vec, from_db);

                // FIXME
                // This fails for now since the conversion code is not fully ready
                // anyhow this is the correct way since sync_handlers convert from storage to proto
                // so we should do proto to storage here
                // use crate::p2p_network::client::v1::conv::TryFromProto;
                // let reply_vec_cloned = reply_vec_cloned.into_iter().map(pathfinder_common::BlockHeader::try_from_proto)
                //     .collect::<anyhow::Result<Vec<_>>>().unwrap();

                // prop_assert_eq!(reply_vec_cloned, from_db_cloned);
            }
        }
    }
}
