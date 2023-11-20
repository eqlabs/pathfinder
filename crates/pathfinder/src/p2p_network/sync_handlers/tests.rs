use p2p_proto::common::{Direction, Step};
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

mod boundary_conditions {
    use super::I64_MAX;
    use crate::p2p_network::sync_handlers::{
        get_bodies, get_events, get_headers, get_receipts, get_transactions, MAX_COUNT_IN_TESTS,
    };
    use assert_matches::assert_matches;
    use fake::{Fake, Faker};
    use p2p_proto::block::{
        BlockBodiesRequest, BlockBodyMessage, BlockHeadersRequest, BlockHeadersResponse,
        BlockHeadersResponsePart,
    };
    use p2p_proto::common::{BlockNumberOrHash, Direction, Fin, Iteration};
    use p2p_proto::event::{EventsRequest, EventsResponseKind};
    use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponseKind};
    use p2p_proto::transaction::{TransactionsRequest, TransactionsResponseKind};
    use pathfinder_storage::fake::with_n_blocks;
    use pathfinder_storage::Storage;
    use rand::{thread_rng, Rng};
    use rstest::rstest;
    use tokio::sync::mpsc;

    mod zero_limit_yields_fin_ok_invalid_start_yields_fin_unknown {
        use super::*;

        fn zero_limit() -> Iteration {
            Iteration {
                limit: 0,
                ..Faker.fake()
            }
        }

        fn invalid_start() -> Iteration {
            Iteration {
                start: BlockNumberOrHash::Number(
                    rand::thread_rng().gen_range(I64_MAX + 1..=u64::MAX),
                ),
                ..Faker.fake()
            }
        }

        macro_rules! define_test {
            ($name:ident, $uut_name:ident, $request:tt) => {
                #[rstest]
                #[case(zero_limit(), Fin::ok())]
                #[case(invalid_start(), Fin::unknown())]
                #[tokio::test]
                async fn $name(#[case] iteration: Iteration, #[case] fin: Fin) {
                    let storage = Storage::in_memory().unwrap();
                    let (tx, mut rx) = mpsc::channel(1);
                    let _jh = tokio::spawn($uut_name(storage, $request { iteration }, tx));
                    assert_eq!(rx.recv().await.unwrap().into_fin(), Some(fin));
                }
            };
        }

        define_test!(headers, get_headers, BlockHeadersRequest);
        define_test!(bodies, get_bodies, BlockBodiesRequest);
        define_test!(transactions, get_transactions, TransactionsRequest);
        define_test!(receipts, get_receipts, ReceiptsRequest);
        define_test!(events, get_events, EventsRequest);
    }

    mod partially_successful_requests_end_with_additional_fin_unknown {
        use super::*;

        fn init_test<T>(
            direction: Direction,
        ) -> (Storage, Iteration, mpsc::Sender<T>, mpsc::Receiver<T>) {
            let storage: Storage = Storage::in_memory().unwrap();
            let _ = with_n_blocks(&storage, 1);
            let iteration = Iteration {
                start: BlockNumberOrHash::Number(0),
                // We want more than available, we don't care about the internal limit because
                // partial failure (`Fin::unknown()`) takes precedence over it (`Fin::too_much()`)
                limit: thread_rng().gen_range(2..=MAX_COUNT_IN_TESTS * 2),
                direction,
                ..Faker.fake()
            };
            let (tx, rx) = mpsc::channel::<T>(1);
            (storage, iteration, tx, rx)
        }

        #[rstest]
        #[tokio::test]
        async fn test_get_headers(
            #[values(Direction::Backward, Direction::Forward)] direction: Direction,
        ) {
            let (storage, iteration, tx, mut rx) = init_test(direction);
            get_headers(storage, BlockHeadersRequest { iteration }, tx)
                .await
                .unwrap();
            let BlockHeadersResponse { parts } = rx.recv().await.unwrap();
            // parts[0] is the header, parts[1] is Fin::ok()
            // Expect Fin::unknown() where the first unavailable item would be
            assert_matches::assert_matches!(&parts[2], BlockHeadersResponsePart::Fin(f) => assert_eq!(f, &Fin::unknown()));
            assert_eq!(parts.len(), 3);
        }

        #[rstest]
        #[tokio::test]
        async fn test_get_bodies(
            #[values(Direction::Backward, Direction::Forward)] direction: Direction,
        ) {
            let (storage, iteration, tx, mut rx) = init_test(direction);
            let _jh = tokio::spawn(get_bodies(storage, BlockBodiesRequest { iteration }, tx));
            rx.recv().await.unwrap(); // Diff
            match rx.recv().await.unwrap().body_message {
                // New classes in block
                BlockBodyMessage::Classes(_) => {
                    rx.recv().await.unwrap(); // Classes, Fin::ok()
                }
                // No new classes in block
                BlockBodyMessage::Fin(_) => {} // Fin::ok()
                _ => panic!("unexpected message type"),
            }

            // Expect Fin::unknown() where the first unavailable item would be
            assert_matches::assert_matches!(rx.recv().await.unwrap().body_message, BlockBodyMessage::Fin(f) => assert_eq!(f, Fin::unknown()));
        }

        macro_rules! define_test {
            ($name:ident, $uut_name:ident, $request:tt, $reply:tt) => {
                #[rstest]
                #[tokio::test]
                async fn $name(#[values(Direction::Backward, Direction::Forward)] direction: Direction) {
                    let (storage, iteration, tx, mut rx) = init_test(direction);
                    let _jh = tokio::spawn($uut_name(
                        storage,
                        $request { iteration },
                        tx,
                    ));
                    rx.recv().await.unwrap(); // Block data
                    rx.recv().await.unwrap(); // Fin::ok()
                    // Expect Fin::unknown() where the first unavailable item would be
                    assert_matches::assert_matches!(
                        rx.recv().await.unwrap().kind,
                        $reply::Fin(f) => assert_eq!(f, Fin::unknown())
                    );
                }
            };
        }

        define_test!(
            test_get_transactions,
            get_transactions,
            TransactionsRequest,
            TransactionsResponseKind
        );
        define_test!(
            test_get_receipts,
            get_receipts,
            ReceiptsRequest,
            ReceiptsResponseKind
        );
        define_test!(
            test_get_events,
            get_events,
            EventsRequest,
            EventsResponseKind
        );
    }

    mod internally_limited_requests_end_with_additional_fin_too_much {
        use super::*;

        const NUM_BLOCKS_IN_STORAGE: u64 = MAX_COUNT_IN_TESTS;

        fn init_test<T>(
            direction: Direction,
        ) -> (Storage, Iteration, mpsc::Sender<T>, mpsc::Receiver<T>) {
            let storage = Storage::in_memory().unwrap();
            let _ = with_n_blocks(&storage, NUM_BLOCKS_IN_STORAGE as usize);
            let (tx, rx) = mpsc::channel::<T>(1);
            let start = match direction {
                Direction::Forward => BlockNumberOrHash::Number(0),
                Direction::Backward => BlockNumberOrHash::Number(NUM_BLOCKS_IN_STORAGE - 1),
            };
            let iteration = Iteration {
                start,
                // We want to trigger the internal limit
                limit: thread_rng().gen_range(NUM_BLOCKS_IN_STORAGE + 1..=u64::MAX),
                step: 1.into(),
                direction,
            };
            (storage, iteration, tx, rx)
        }

        #[rstest]
        #[tokio::test]
        async fn test_get_headers(
            #[values(Direction::Backward, Direction::Forward)] direction: Direction,
        ) {
            let (storage, iteration, tx, mut rx) = init_test(direction);
            get_headers(storage, BlockHeadersRequest { iteration }, tx.clone())
                .await
                .unwrap();

            let BlockHeadersResponse { parts } = rx.recv().await.unwrap();
            // parts[0..20] are 10 x [header + Fin::ok()]
            // Expect Fin::too_much() if all requested items were found up to the internal limit
            assert_matches!(&parts[NUM_BLOCKS_IN_STORAGE as usize * 2], BlockHeadersResponsePart::Fin(f) => assert_eq!(f, &Fin::too_much()));
            assert_eq!(parts.len(), NUM_BLOCKS_IN_STORAGE as usize * 2 + 1);
        }

        #[rstest]
        #[tokio::test]
        async fn test_get_bodies(
            #[values(Direction::Backward, Direction::Forward)] direction: Direction,
        ) {
            let (storage, iteration, tx, mut rx) = init_test(direction);
            let _jh = tokio::spawn(get_bodies(storage, BlockBodiesRequest { iteration }, tx));
            // 10 x [Diff, Classes*, Fin::ok()]
            for _ in 0..NUM_BLOCKS_IN_STORAGE {
                rx.recv().await.unwrap(); // Diff
                match rx.recv().await.unwrap().body_message {
                    // New classes in block
                    BlockBodyMessage::Classes(_) => {
                        rx.recv().await.unwrap(); // Classes, Fin::ok()
                    }
                    // No new classes in block
                    BlockBodyMessage::Fin(_) => {} // Fin::ok()
                    _ => panic!("unexpected message type"),
                }
            }
            // Expect Fin::unknown() where the first unavailable item would be
            assert_matches::assert_matches!(
                rx.recv().await.unwrap().body_message,
                BlockBodyMessage::Fin(f) => assert_eq!(f, Fin::too_much())
            );
        }

        macro_rules! define_test {
            ($name:ident, $uut_name:ident, $request:tt, $reply:tt) => {
                #[rstest]
                #[tokio::test]
                async fn $name(#[values(Direction::Backward, Direction::Forward)] direction: Direction) {
                    let (storage, iteration, tx, mut rx) = init_test(direction);
                    let _jh = tokio::spawn($uut_name(
                        storage,
                        $request { iteration },
                        tx,
                    ));
                    for _ in 0..NUM_BLOCKS_IN_STORAGE {
                        rx.recv().await.unwrap(); // Block data
                        rx.recv().await.unwrap(); // Fin::ok()
                    }
                    // Expect Fin::unknown() where the first unavailable item would be
                    assert_matches::assert_matches!(
                        rx.recv().await.unwrap().kind,
                        $reply::Fin(f) => assert_eq!(f, Fin::too_much())
                    );
                }
            };
        }

        define_test!(
            test_get_transactions,
            get_transactions,
            TransactionsRequest,
            TransactionsResponseKind
        );
        define_test!(
            test_get_receipts,
            get_receipts,
            ReceiptsRequest,
            ReceiptsResponseKind
        );
        define_test!(
            test_get_events,
            get_events,
            EventsRequest,
            EventsResponseKind
        );
    }
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    use crate::p2p_network::client::types as simplified;
    use crate::p2p_network::sync_handlers::blocking;
    use p2p::client::types::{self as p2p_types, TryFromDto};
    use p2p_proto::block::{
        BlockBodiesRequest, BlockBodyMessage, BlockHeadersRequest, BlockHeadersResponse,
        BlockHeadersResponsePart,
    };
    use p2p_proto::common::{BlockId, BlockNumberOrHash, Error, Fin, Iteration};
    use p2p_proto::event::{EventsRequest, EventsResponseKind};
    use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponseKind};
    use p2p_proto::transaction::{TransactionsRequest, TransactionsResponseKind};
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
            let BlockHeadersResponse { parts } = blocking::get_headers(tx, request).unwrap();
            // Empty reply in the test is only possible if the request does not overlap with storage
            // Invalid start and zero limit are tested in boundary_conditions::
            if expected.is_empty() {
                prop_assert_eq!(parts.len(), 1);
                prop_assert_eq!(parts[0].clone().into_fin().unwrap(), Fin::unknown());
            } else {
                // Group reply parts by block: [[hdr-0, fin-0], [hdr-1, fin-1], ...]
                let actual = parts.chunks_exact(2).map(|parts| {
                    // Make sure block data is delimited
                    assert_eq!(parts[1], BlockHeadersResponsePart::Fin(Fin::ok()));
                    // Extract the header
                    p2p_types::BlockHeader::try_from(parts[0].clone().into_header().unwrap()).unwrap()
                }).collect::<Vec<_>>();

                prop_assert_eq!(actual, expected);
            }
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
            ).collect::<HashMap<_, (p2p_types::StateUpdate, HashMap<ClassHash, Vec<u8>>)>>();
            // Run the handler
            let request = BlockBodiesRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let replies = blocking::get_bodies(tx, request).unwrap();
            // Empty reply is only possible if the request does not overlap with storage
            // Invalid start and zero limit are tested in boundary_conditions::
            if expected.is_empty() {
                prop_assert_eq!(replies.len(), 1);
                prop_assert_eq!(replies[0].clone().into_fin().unwrap(), Fin::unknown());
            } else {
                // Collect replies into a set of (block_number, state_update, definitions)
                let mut actual = HashMap::new();
                let mut block_id = None;

                for reply in replies {
                    match reply.body_message {
                        BlockBodyMessage::Diff(d) => {
                            let BlockId { number, hash } = reply.id.unwrap();
                            block_id = Some((BlockNumber::new(number).unwrap(), BlockHash(hash.0)));

                            let state_update = p2p_types::StateUpdate::from(d);
                            actual.insert(block_id.unwrap(), (state_update, HashMap::new()));
                        },
                        BlockBodyMessage::Classes(c) => {
                            // Classes coming after a state diff should be for the same block
                            let entry = actual.get_mut(&block_id.expect("Classes follow Diff so current block id should be set")).unwrap();
                            entry.1.extend(c.classes.into_iter().map(|c|
                                (
                                    ClassHash(c.compiled_hash.0),
                                    zstd::decode_all(&c.definition[..]).unwrap()
                                )
                            ));
                        },
                        BlockBodyMessage::Fin(f) => {
                            match f.error {
                                // We either managed to fit the entire range or we hit the internal limit
                                None | Some(Error::TooMuch) => assert!(actual.contains_key(&block_id.unwrap())),
                                // Either the request yielded nothing or was only partially successful
                                Some(Error::Unknown) => {},
                                Some(_) => panic!("unexpected error"),
                            }
                        }
                        _ => unimplemented!(),
                    }
                }

                prop_assert_eq!(actual, expected);
            }
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
            let replies = blocking::get_transactions(tx, request).unwrap();
            // Empty reply is only possible if the request does not overlap with storage
            // Invalid start and zero limit are tested in boundary_conditions::
            if expected.is_empty() {
                prop_assert_eq!(replies.len(), 1);
                prop_assert_eq!(replies[0].clone().into_fin().unwrap(), Fin::unknown());
            } else {
                // Group replies by block, it is assumed that transactions per block are small enough to fit under the 1MiB limit
                // This means that there are 2 replies per block: [[transactions-0, fin-0], [transactions-1, fin-1], ...]
                let actual = replies.chunks_exact(2).map(|replies | {
                    assert_eq!(replies[0].id, replies[1].id);
                    // Make sure block data is delimited
                    assert_eq!(replies[1].kind, TransactionsResponseKind::Fin(Fin::ok()));
                    // Extract transactions
                    let transactions = replies[0].kind.clone().into_transactions().unwrap().items;
                    let BlockId { number, hash } = replies[0].id.unwrap();
                    (
                        BlockNumber::new(number).unwrap(),
                        BlockHash(hash.0),
                        transactions.into_iter().map(|t| TransactionVariant::try_from_dto(t).unwrap()).collect::<Vec<_>>()
                    )
                }).collect::<Vec<_>>();

                prop_assert_eq!(actual, expected);
            }
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
            // These are the receipts that we expect to be read from the db
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
            let replies = blocking::get_receipts(tx, request).unwrap();
            // Empty reply is only possible if the request does not overlap with storage
            // Invalid start and zero limit are tested in boundary_conditions::
            if expected.is_empty() {
                prop_assert_eq!(replies.len(), 1);
                prop_assert_eq!(replies[0].clone().into_fin().unwrap(), Fin::unknown());
            } else {
                // Group replies by block, it is assumed that receipts per block small enough to fit under the 1MiB limit
                // This means that there are 2 replies per block: [[receipts-0, fin-0], [receipts-1, fin-1], ...]
                let actual = replies.chunks_exact(2).map(|replies | {
                    assert_eq!(replies[0].id, replies[1].id);
                    // Make sure block data is delimited
                    assert_eq!(replies[1].kind, ReceiptsResponseKind::Fin(Fin::ok()));
                    // Extract receipts
                    let receipts = replies[0].kind.clone().into_receipts().unwrap().items;
                    let BlockId { number, hash } = replies[0].id.unwrap();
                    (
                        BlockNumber::new(number).unwrap(),
                        BlockHash(hash.0),
                        receipts.into_iter().map(|r| simplified::Receipt::try_from(r).unwrap()).collect::<Vec<_>>()
                    )
                }).collect::<Vec<_>>();

                prop_assert_eq!(actual, expected);
            }
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
            let replies = blocking::get_events(tx, request).unwrap();
            // Empty reply is only possible if the request does not overlap with storage
            // Invalid start and zero limit are tested in boundary_conditions::
            if expected.is_empty() {
                prop_assert_eq!(replies.len(), 1);
                prop_assert_eq!(replies[0].clone().into_fin().unwrap(), Fin::unknown());
            } else {
                // Group replies by block, it is assumed that events per block small enough to fit under the 1MiB limit
                // This means that there are 2 replies per block: [[events-0, fin-0], [events-1, fin-1], ...]
                let actual = replies.chunks_exact(2).map(|replies | {
                    assert_eq!(replies[0].id, replies[1].id);
                    // Make sure block data is delimited
                    assert_eq!(replies[1].kind, EventsResponseKind::Fin(Fin::ok()));
                    // Extract events
                    let events = replies[0].kind.clone().into_events().unwrap().items;
                    let BlockId { number, hash } = replies[0].id.unwrap();
                    (
                        BlockNumber::new(number).unwrap(),
                        BlockHash(hash.0),
                        events.into_iter().map(|e|
                            (
                                TransactionHash(e.transaction_hash.0),
                                e.events.into_iter().map(|e| Event::try_from_dto(e).unwrap()).collect::<Vec<_>>()
                            )).collect::<Vec<_>>()
                    )
                }).collect::<Vec<_>>();

                prop_assert_eq!(actual, expected);
            }
        }
    }

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
        use p2p_proto::common::{Direction, Step};
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
        use super::fixtures::MAX_NUM_BLOCKS;
        use crate::p2p_network::sync_handlers::tests::I64_MAX;
        use p2p_proto::common::{Direction, Step};
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
                // Occurrence 4:1
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
                    direction in prop_oneof![Just(Direction::Forward), Just(Direction::Backward)],
                ) -> (u64, u64, u64, u64, Step, Direction) {
                (num_blocks, storage_seed, start, limit, step.into(), direction)
            }
        }
    }
}

mod classes {
    use crate::p2p_network::sync_handlers::{classes, ClassId};
    use fake::{Fake, Faker};
    use p2p_proto::common::BlockId;

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
        use p2p_proto::block::BlockBodyMessage::Classes;
        use p2p_proto::common::Hash;
        use p2p_proto::consts::{CLASSES_MESSAGE_OVERHEAD, MESSAGE_SIZE_LIMIT, PER_CLASS_OVERHEAD};
        use p2p_proto::state::Class;

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
        let class_ids = fake::vec![ClassId; defs.len()];
        let mut def_it = defs.clone().into_iter();
        let class_definition_getter = |_, _| Ok(def_it.next().unwrap());

        let mut responses = vec![];
        // UUT
        assert!(classes(
            block_number,
            block_hash,
            class_ids.clone(),
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

        let definition = |i| {
            let (compiled_hash, casm_hash) = (class_ids[i] as ClassId).into_dto();
            Class {
                compiled_hash,
                definition: (&defs[i] as &Vec<u8>).clone(),
                casm_hash,
                total_parts: None,
                part_num: None,
            }
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
