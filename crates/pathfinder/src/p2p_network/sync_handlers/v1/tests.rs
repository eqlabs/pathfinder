use crate::p2p_network::sync_handlers::v1::{get_bodies, get_headers};
use assert_matches::assert_matches;
use fake::{Fake, Faker};
use p2p_proto_v1::block::{BlockBodiesRequest, BlockHeadersRequest};
use p2p_proto_v1::common::{Direction, Iteration, Step};
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
    use rand::Rng;
    #[rustfmt::skip] fn zero_limit() -> Iteration { Iteration { limit: 0, ..Faker.fake() } }
    #[rustfmt::skip] fn invalid_start() -> Iteration { Iteration { start_block: rand::thread_rng().gen_range(I64_MAX + 1..=u64::MAX), ..Faker.fake() } }

    #[rstest]
    #[case(zero_limit())]
    #[case(invalid_start())]
    #[tokio::test]
    async fn headers(#[case] iteration: Iteration) {
        let storage = Storage::in_memory().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        // Clone the sender to make sure that the channel is not prematurely closed
        get_headers(&storage, BlockHeadersRequest { iteration }, tx.clone())
            .await
            .unwrap();
        // No reply should be sent
        assert_matches!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }

    #[rstest]
    #[case(zero_limit())]
    #[case(invalid_start())]
    #[tokio::test]
    async fn bodies(#[case] iteration: Iteration) {
        let storage = Storage::in_memory().unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        // Clone the sender to make sure that the channel is not prematurely closed
        get_bodies(&storage, BlockBodiesRequest { iteration }, tx.clone())
            .await
            .unwrap();
        // No reply should be sent
        assert_matches!(rx.try_recv().unwrap_err(), TryRecvError::Empty);
    }
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    use crate::p2p_network::client::v1::conv::{BlockHeader, TryFromProto};
    use crate::p2p_network::sync_handlers::v1::headers;
    use p2p_proto_v1::block::BlockHeadersRequest;
    use p2p_proto_v1::common::{Direction, Iteration};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn get_headers((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            // These are the headers that we expect to be read from the db
            let expected = match direction {
                Direction::Forward => overlapping::forward(in_db, start_block, limit, step).map(|(h, _, _)| h.into()).collect::<Vec<_>>(),
                Direction::Backward => overlapping::backward(in_db, start_block, limit, step, num_blocks).map(|(h, _, _)| h.into()).collect::<Vec<_>>(),
            };
            // Run the handler
            let request = BlockHeadersRequest { iteration: Iteration { start_block, limit, step, direction, } };
            let reply = headers(tx, request).unwrap();
            // Extract headers from the reply
            let actual = reply.into_iter().map(|reply | {
                let header = reply.header_message.into_header().unwrap();
                assert_eq!(reply.block_number, header.number);
                BlockHeader::try_from_proto(header)
            }).collect::<anyhow::Result<Vec<_>>>().unwrap();

            prop_assert_eq!(actual, expected);
        }
    }

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
        use p2p_proto_v1::common::Step;
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

        pub fn backward(
            mut from_db: StorageInitializer,
            start_block: u64,
            limit: u64,
            step: Step,
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
                .step_by(step.take_inner().try_into().unwrap())
                .take(std::cmp::min(limit, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }
    }

    /// Building blocks for the ultimate composite strategy used in all property tests
    mod strategy {
        use crate::p2p_network::sync_handlers::v1::tests::I64_MAX;

        use super::fixtures::MAX_NUM_BLOCKS;
        use p2p_proto_v1::common::{Direction, Step};
        use proptest::prelude::*;
        use std::ops::Range;

        prop_compose! {
            fn inside(range: Range<u64>)(x in range) -> u64 { x }
        }

        prop_compose! {
            fn outside_le(range: Range<u64>, max: u64)(x in range.end..=max) -> u64 { x }
        }

        fn rarely_outside_le(range: std::ops::Range<u64>, max: u64) -> BoxedStrategy<u64> {
            // Empty range will trigger a panic in rand::distributions::Uniform
            if range.is_empty() {
                return Just(range.start).boxed();
            }

            prop_oneof![
                // Occurance 4:1
                4 => inside(range.clone()),
                1 => outside_le(range, max),
            ]
            .boxed()
        }

        fn rarely_outside(range: std::ops::Range<u64>) -> BoxedStrategy<u64> {
            rarely_outside_le(range, u64::MAX)
        }

        prop_compose! {
            pub fn composite()
                (num_blocks in 0..MAX_NUM_BLOCKS)
                (
                    num_blocks in Just(num_blocks),
                    storage_seed in any::<u64>(),
                    // out of range (> i64::MAX) start values are tested in `empty_reply::`
                    start in rarely_outside_le(0..num_blocks, I64_MAX),
                    // limit of 0 is tested in `empty_reply::`
                    limit in rarely_outside(1..num_blocks),
                    // step is always >= 1
                    step in rarely_outside(1..num_blocks / 4),
                    directon in prop_oneof![Just(Direction::Forward), Just(Direction::Backward)],
                ) -> (u64, u64, u64, u64, Step, Direction) {
                (num_blocks, storage_seed, start, limit, step.into(), directon)
            }
        }
    }
}
