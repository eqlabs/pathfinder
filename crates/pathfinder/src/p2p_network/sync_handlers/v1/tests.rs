use p2p_proto_v1::common::{Direction, Step};
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

mod empty_reply {
    use super::I64_MAX;
    use crate::p2p_network::sync_handlers::v1::{
        get_bodies, get_events, get_headers, get_receipts, get_transactions,
    };
    use fake::{Fake, Faker};
    use p2p_proto_v1::block::{BlockBodiesRequest, BlockHeadersRequest};
    use p2p_proto_v1::common::{BlockNumberOrHash, Fin, Iteration};
    use p2p_proto_v1::event::EventsRequest;
    use p2p_proto_v1::receipt::ReceiptsRequest;
    use p2p_proto_v1::transaction::TransactionsRequest;
    use pathfinder_storage::Storage;
    use rand::Rng;
    use rstest::rstest;
    use tokio::sync::mpsc;

    fn zero_limit() -> Iteration {
        Iteration {
            limit: 0,
            ..Faker.fake()
        }
    }

    fn invalid_start() -> Iteration {
        Iteration {
            start: BlockNumberOrHash::Number(rand::thread_rng().gen_range(I64_MAX + 1..=u64::MAX)),
            ..Faker.fake()
        }
    }

    macro_rules! define_test {
        ($name:ident, $uut_name:ident, $request:tt) => {
            #[rstest]
            #[case(zero_limit())]
            #[case(invalid_start())]
            #[tokio::test]
            async fn $name(#[case] iteration: Iteration) {
                let storage = Storage::in_memory().unwrap();
                let (tx, mut rx) = mpsc::channel(1);
                // Clone the sender to make sure that the channel is not prematurely closed
                $uut_name(&storage, $request { iteration }, tx.clone())
                    .await
                    .unwrap();
                assert_eq!(rx.recv().await.unwrap().into_fin(), Some(Fin::unknown()));
            }
        };
    }

    define_test!(headers, get_headers, BlockHeadersRequest);
    define_test!(bodies, get_bodies, BlockBodiesRequest);
    define_test!(transactions, get_transactions, TransactionsRequest);
    define_test!(receipts, get_receipts, ReceiptsRequest);
    define_test!(events, get_events, EventsRequest);
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    use crate::p2p_network::client::v1::conv::{self as simplified, TryFromProto};
    use crate::p2p_network::sync_handlers::v1::{bodies, events, headers, receipts, transactions};
    use p2p_proto_v1::block::{
        BlockBodiesRequest, BlockBodyMessage, BlockHeadersRequest, BlockHeadersResponse,
        BlockHeadersResponsePart,
    };
    use p2p_proto_v1::common::{BlockId, BlockNumberOrHash, Fin, Iteration};
    use p2p_proto_v1::event::EventsRequest;
    use p2p_proto_v1::receipt::ReceiptsRequest;
    use p2p_proto_v1::transaction::TransactionsRequest;
    use pathfinder_common::event::Event;
    use pathfinder_common::transaction::{Transaction, TransactionVariant};
    use pathfinder_common::{BlockHash, BlockNumber, ClassHash, TransactionHash};
    use proptest::prelude::*;
    use std::collections::HashMap;

    proptest! {
        #[test]
        fn get_headers((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            // Compute the overlapping set between the db and the request
            // These are the headers that we expect to be read from the db
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction)
                .into_iter().map(|(h, _, _, _, _)| h.into()).collect::<Vec<_>>();
            // Run the handler
            let request = BlockHeadersRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let BlockHeadersResponse { parts } = headers(tx, request).unwrap();
            // Group reply parts by block
            let parts_by_block = parts.chunks_exact(2);
            let actual = parts_by_block.clone().map(|part | {
                // Make sure block data is delimited
                assert_eq!(part[1], BlockHeadersResponsePart::Fin(Fin::ok()));
                // Extract the header
                simplified::BlockHeader::try_from_proto(part[0].clone().into_header().unwrap()).unwrap()
            }).collect::<Vec<_>>();
            prop_assert_eq!(actual, expected);
        }
    }

    proptest! {
        #[test]
        fn get_bodies((num_blocks, db_seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(db_seed, num_blocks);
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            // Get the overlapping set between the db and the request
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|(header, _, state_update, cairo_defs, sierra_defs)|
                    (
                        (header.number, header.hash),
                        (state_update.into(),
                        cairo_defs.into_iter().chain(sierra_defs.into_iter().map(|(h, d)| (ClassHash(h.0), d))).collect())
                    )
            ).collect::<HashMap<_, (simplified::StateUpdate, HashMap<ClassHash, Vec<u8>>)>>();
            // Run the handler
            let request = BlockBodiesRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let replies = bodies(tx, request).unwrap().into_iter();
            // Collect replies into a set of (block_number, state_update, definitions)
            let mut actual = HashMap::new();

            for reply in replies {
                let BlockId { number, hash } = reply.id.unwrap();
                let block_id = (BlockNumber::new(number).unwrap(), BlockHash(hash.0));

                match reply.body_message {
                    BlockBodyMessage::Diff(d) => {
                        let state_update = simplified::StateUpdate::try_from_proto(d).unwrap();
                        actual.insert(block_id, (state_update, HashMap::new()));
                    },
                    BlockBodyMessage::Classes(c) => {
                        // Classes coming after a state diff should be for the same block
                        let entry = actual.get_mut(&block_id).unwrap();
                        entry.1.extend(c.classes.into_iter().map(|c|
                            (
                                ClassHash(c.compiled_hash.0),
                                zstd::decode_all(&c.definition[..]).unwrap()
                            )
                        ));
                    },
                    _ => panic!("unexpected message type"),
                }
            }

            prop_assert_eq!(actual, expected);
        }
    }

    mod workaround {
        use pathfinder_common::{TransactionNonce, TransactionVersion};
        use starknet_gateway_types::reply::transaction as gw;

        // Align with the deserialization workaround to avoid false negative mismatches
        pub fn for_legacy_l1_handlers(tx: gw::Transaction) -> gw::Transaction {
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
    }

    proptest! {
        #[test]
        fn get_transactions((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            // Compute the overlapping set between the db and the request
            // These are the transactions that we expect to be read from the db
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|(h, tr, _, _, _)|
                    (
                        h.number,
                        h.hash,
                        tr.into_iter().map(|(t, _)| Transaction::from(workaround::for_legacy_l1_handlers(t)).variant).collect::<Vec<_>>()
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = TransactionsRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let replies = transactions(tx, request).unwrap();
            // Extract transactions from the replies
            let actual = replies.into_iter().map(|reply | {
                let transactions = reply.kind.into_transactions().unwrap().items;
                let BlockId { number, hash } = reply.id.unwrap();
                (
                    BlockNumber::new(number).unwrap(),
                    BlockHash(hash.0),
                    transactions.into_iter().map(|t| TransactionVariant::try_from_proto(t).unwrap()).collect::<Vec<_>>()
                )
            }).collect::<Vec<_>>();

            prop_assert_eq!(actual, expected);
        }
    }

    proptest! {
        #[test]
        fn get_receipts((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            // Compute the overlapping set between the db and the request
            // These are the transactions that we expect to be read from the db
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|(h, tr, _, _, _)|
                    (
                        h.number,
                        h.hash,
                        tr.into_iter().map(|(_, r)| r.into()).collect::<Vec<_>>()
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = ReceiptsRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let replies = receipts(tx, request).unwrap();
            // Extract transactions from the replies
            let actual = replies.into_iter().map(|reply | {
                let receipts = reply.kind.into_receipts().unwrap().items;
                let BlockId { number, hash } = reply.id.unwrap();
                (
                    BlockNumber::new(number).unwrap(),
                    BlockHash(hash.0),
                    receipts.into_iter().map(|r| simplified::Receipt::try_from_proto(r).unwrap()).collect::<Vec<_>>()
                )
            }).collect::<Vec<_>>();

            prop_assert_eq!(actual, expected);
        }
    }

    proptest! {
        #[test]
        fn get_events((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            let mut connection = storage.connection().unwrap();
            let tx = connection.transaction().unwrap();
            // Compute the overlapping set between the db and the request
            // These are the events that we expect to be read from the db
            // Extract tuples (block_number, block_hash, [events{txn#1}, events{txn#2}, ...])
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|(h, tr, _, _, _)|
                    (
                        h.number,
                        h.hash,
                        tr.into_iter().map(|(_, r)| (r.transaction_hash, r.events)).collect::<Vec<_>>()
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = EventsRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let replies = events(tx, request).unwrap();
            // Extract events from the replies
            let actual = replies.into_iter().map(|reply | {
                let events = reply.responses.into_events().unwrap().items;
                let BlockId { number, hash } = reply.id.unwrap();
                (
                    BlockNumber::new(number).unwrap(),
                    BlockHash(hash.0),
                    events.into_iter().map(|e|
                        (
                            TransactionHash(e.transaction_hash.0),
                            e.events.into_iter().map(|e| Event::try_from_proto(e).unwrap()).collect::<Vec<_>>()
                        )).collect::<Vec<_>>()
                )
            }).collect::<Vec<_>>();

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
        use p2p_proto_v1::common::{Direction, Step};
        use pathfinder_storage::fake::{StorageInitializer, StorageInitializerItem};

        pub fn get(
            from_db: StorageInitializer,
            start_block: u64,
            limit: u64,
            step: Step,
            num_blocks: u64,
            direction: Direction,
        ) -> StorageInitializer {
            match direction {
                Direction::Forward => forward(from_db, start_block, limit, step).collect(),
                Direction::Backward => {
                    backward(from_db, start_block, limit, step, num_blocks).collect()
                }
            }
        }

        fn forward(
            from_db: StorageInitializer,
            start_block: u64,
            limit: u64,
            step: Step,
        ) -> impl Iterator<Item = StorageInitializerItem> {
            from_db
                .into_iter()
                .skip(start_block.try_into().unwrap())
                .step_by(step.into_inner().try_into().unwrap())
                .take(std::cmp::min(limit, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }

        fn backward(
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
                .step_by(step.into_inner().try_into().unwrap())
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

mod classes {
    use crate::p2p_network::sync_handlers::v1::classes;
    use fake::{Fake, Faker};
    use p2p_proto_v1::common::BlockId;
    use pathfinder_common::ClassHash;

    #[test]
    fn empty_input_yields_empty_output() {
        let mut responses = vec![];
        assert!(classes(
            Faker.fake(),
            Faker.fake(),
            vec![],
            &mut responses,
            |_, _| Ok(vec![]),
        )
        .is_ok());
        assert!(responses.is_empty());
    }

    #[test]
    fn getter_error_yields_error() {
        let mut responses = vec![];
        assert!(classes(
            Faker.fake(),
            Faker.fake(),
            vec![Faker.fake()],
            &mut responses,
            |_, _| anyhow::bail!("getter failed"),
        )
        .is_err());
        assert!(responses.is_empty());
    }

    #[test]
    fn batching_and_partitioning() {
        use p2p_proto_v1::block::BlockBodyMessage::Classes;
        use p2p_proto_v1::common::Hash;
        use p2p_proto_v1::consts::{
            CLASSES_MESSAGE_OVERHEAD, MESSAGE_SIZE_LIMIT, PER_CLASS_OVERHEAD,
        };
        use p2p_proto_v1::state::Class;

        // Max size of definition that can be stored in one message
        const FULL: usize = MESSAGE_SIZE_LIMIT - CLASSES_MESSAGE_OVERHEAD - PER_CLASS_OVERHEAD;
        const SMALL: usize = FULL / 10;
        const BIG: usize = MESSAGE_SIZE_LIMIT * 3;
        let not_full = fake::vec![u8; 1..FULL];

        let block_number = Faker.fake();
        let block_hash = Faker.fake();
        let defs = vec![
            // Small ones are batched
            fake::vec![u8; 1..=SMALL],
            fake::vec![u8; 1..=SMALL],
            // The biggest that fits into one msg is not artificially partitioned and glued to the previous message
            fake::vec![u8; FULL],
            // Two that fit exactly into one msg
            fake::vec![u8; FULL - not_full.len() - PER_CLASS_OVERHEAD],
            not_full,
            // A small one has to be put in the next message as there's no space left
            fake::vec![u8; 1..=SMALL],
            // Big one, should be chunked, but the first chunk should not be glued to the previous message
            fake::vec![u8; BIG],
            // Small one again, is not glued to the last chunk of the previous partitioned definition, no matter how small that chunk is
            fake::vec![u8; 1..=SMALL],
        ];
        let class_hashes = fake::vec![ClassHash; defs.len()];
        let mut def_it = defs.clone().into_iter();
        let class_definition_getter = |_, _| Ok(def_it.next().unwrap());

        let mut responses = vec![];
        // UUT
        assert!(classes(
            block_number,
            block_hash,
            class_hashes.clone(),
            &mut responses,
            class_definition_getter,
        )
        .is_ok());

        // Extract class definition responses, perform basic checks
        let responses = responses
            .into_iter()
            .map(|r| {
                assert_eq!(
                    r.id,
                    Some(BlockId {
                        number: block_number.get(),
                        hash: Hash(block_hash.0)
                    })
                );
                match r.body_message {
                    Classes(c) => {
                        assert_eq!(c.domain, 0, "FIXME figure out what the domain id should be");
                        c.classes
                    }
                    _ => panic!("unexpected message type"),
                }
            })
            .collect::<Vec<_>>();

        let definition = |i| Class {
            compiled_hash: Hash((class_hashes[i] as ClassHash).0),
            definition: (&defs[i] as &Vec<u8>).clone(),
            total_parts: None,
            part_num: None,
        };
        let part = |i, d: &[u8], t, p| Class {
            definition: d.to_vec(),
            total_parts: Some(t),
            part_num: Some(p),
            ..definition(i)
        };
        // Small ones are batched
        assert_eq!(responses[0], vec![definition(0), definition(1),]);
        // The biggest that fits into one msg is not artificially partitioned and glued to the previous message
        assert_eq!(responses[1], vec![definition(2)]);
        // Two that fit exactly into one msg
        assert_eq!(responses[2], vec![definition(3), definition(4)]);
        // A small one has to be put in the next message as there's no space left
        assert_eq!(responses[3], vec![definition(5)]);
        // Big one, should be chunked, but the first chunk should not be glued to the previous message
        assert_eq!(responses[4], vec![part(6, &defs[6][..FULL], 4, 0),]);
        assert_eq!(responses[5], vec![part(6, &defs[6][FULL..2 * FULL], 4, 1),]);
        assert_eq!(
            responses[6],
            vec![part(6, &defs[6][2 * FULL..3 * FULL], 4, 2),]
        );
        assert_eq!(responses[7], vec![part(6, &defs[6][3 * FULL..], 4, 3),]);
        // Small one again, is not glued to the last chunk of the previous partitioned definition, no matter how small that chunk is
        assert_eq!(responses[8], vec![definition(7)]);
    }
}
