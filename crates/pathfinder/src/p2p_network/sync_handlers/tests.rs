use p2p_proto::block::{Direction, Step};
use pathfinder_common::BlockNumber;
use rstest::rstest;

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

// TODO test other requests too
mod empty_reply {
    use crate::p2p_network::sync_handlers::get_headers;
    use assert_matches::assert_matches;
    use fake::{Fake, Faker};
    use p2p_proto::block::{GetBlockHeaders, Iteration};
    use pathfinder_storage::Storage;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::error::TryRecvError;

    #[tokio::test]
    async fn limit_is_zero() {
        let storage = Storage::in_memory().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let request = GetBlockHeaders {
            iteration: Iteration {
                limit: 0,
                ..Faker.fake()
            },
        };
        // Clone the sender to make sure that the channel is not prematurely closed
        get_headers(&storage, request, tx.clone()).await.unwrap();
        // No reply should be sent
        assert_matches!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[tokio::test]
    async fn start_block_larger_than_i64max() {
        let request = GetBlockHeaders {
            iteration: Iteration {
                limit: 0,
                ..Faker.fake()
            },
        };
        let (tx, mut rx) = mpsc::channel(1);
        let storage = Storage::in_memory().unwrap();
        get_headers(&storage, request, tx.clone()).await.unwrap();
        assert_matches!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    /// Fixtures for prop tests
    mod fixtures {
        use crate::p2p_network::sync_handlers::MAX_COUNT_IN_TESTS;
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
        use crate::p2p_network::sync_handlers::MAX_COUNT_IN_TESTS;
        use pathfinder_storage::fake::{StorageInitializer, StorageInitializerItem};

        pub fn forward(
            from_db: StorageInitializer,
            start_block: u64,
            limit: u64,
            skip: u64,
            step: u64,
        ) -> impl Iterator<Item = StorageInitializerItem> {
            from_db
                .into_iter()
                .skip(start_block.try_into().unwrap())
                .skip(skip.try_into().unwrap())
                .step_by(step.try_into().unwrap())
                .take(std::cmp::min(limit, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }
    }

    /// Strategies used in tests
    mod strategy {
        use super::fixtures::MAX_NUM_BLOCKS;
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
                    skip in rarely_outside(0..num_blocks / 4),
                    // step is corrected to always be >= 1
                    step in rarely_outside(1..num_blocks / 4),
                ) -> (u64, u64, u64, u64, u64, u64) {
                (num_blocks, storage_seed, start, limit, skip, step)
            }
        }
    }

    // mod get_blocks {
    //     use super::fixtures::storage_with_seed;
    //     use super::overlapping;
    //     use crate::p2p_network::sync_handlers::headers;
    //     use p2p_proto::block::{Direction, GetBlocks};
    //     use p2p_proto::common::BlockId;
    //     use proptest::prelude::*;

    //     proptest! {
    //         #[test]
    //         fn forward((num_blocks, seed, start, limit, skip, step) in super::strategy::forward()) {
    //             eprintln!("num_blocks: {num_blocks} start: {start} limit: {limit} skip: {skip} step: {step}");
    //             let (storage, from_db) = storage_with_seed(seed, num_blocks);
    //             let from_db = overlapping::forward(from_db, start, limit, skip, step).map(|(header, _, _)| header).collect::<Vec<_>>();

    //             let request = GetBlocks {
    //                 start: BlockId::Height(start),
    //                 direction: Direction::Forward,
    //                 limit,
    //                 skip,
    //                 step,
    //             };

    //             let mut connection = storage.connection().unwrap();
    //             let tx = connection.transaction().unwrap();
    //             let reply = headers(tx, request).unwrap();
    //         }
    //     }
    // }
}
