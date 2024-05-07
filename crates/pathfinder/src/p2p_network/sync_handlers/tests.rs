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

#[cfg(test)]
mod boundary_conditions {
    use fake::{Fake, Faker};
    use futures::channel::mpsc;
    use futures::StreamExt;
    use p2p_proto::class::ClassesRequest;
    use p2p_proto::common::{BlockNumberOrHash, Iteration};
    use p2p_proto::event::EventsRequest;
    use p2p_proto::header::BlockHeadersRequest;
    use p2p_proto::state::StateDiffsRequest;
    use p2p_proto::transaction::TransactionsRequest;
    use pathfinder_storage::StorageBuilder;
    use rand::Rng;
    use rstest::rstest;

    use super::I64_MAX;
    use crate::p2p_network::sync_handlers::{
        get_classes,
        get_events,
        get_headers,
        get_state_diffs,
        get_transactions,
    };

    mod zero_limit_yields_fin_invalid_start_yields_fin {

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
                #[case(zero_limit())]
                #[case(invalid_start())]
                #[tokio::test]
                async fn $name(#[case] iteration: Iteration) {
                    let storage = StorageBuilder::in_memory().unwrap();
                    let (tx, mut rx) = mpsc::channel(0);
                    let _jh = tokio::spawn($uut_name(storage, $request { iteration }, tx));
                    assert_eq!(rx.next().await.unwrap(), Default::default());
                }
            };
        }

        define_test!(headers, get_headers, BlockHeadersRequest);
        define_test!(bodies, get_classes, ClassesRequest);
        define_test!(state_diffs, get_state_diffs, StateDiffsRequest);
        define_test!(transactions, get_transactions, TransactionsRequest);
        define_test!(events, get_events, EventsRequest);
    }
}

/// Property tests, grouped to be immediately visible when executed
mod prop {
    use std::collections::HashMap;

    use futures::channel::mpsc;
    use futures::StreamExt;
    use p2p::client::conv::{CairoDefinition, SierraDefinition, TryFromDto};
    use p2p_proto::class::{Class, ClassesRequest, ClassesResponse};
    use p2p_proto::common::{BlockNumberOrHash, Iteration};
    use p2p_proto::event::{EventsRequest, EventsResponse};
    use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse};
    use p2p_proto::state::{
        ContractDiff,
        ContractStoredValue,
        StateDiffsRequest,
        StateDiffsResponse,
    };
    use p2p_proto::transaction::{
        TransactionWithReceipt,
        TransactionsRequest,
        TransactionsResponse,
    };
    use pathfinder_common::event::Event;
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::state_update::SystemContractUpdate;
    use pathfinder_common::transaction::TransactionVariant;
    use pathfinder_common::{
        ClassCommitment,
        ClassHash,
        ContractAddress,
        ContractNonce,
        SierraHash,
        SignedBlockHeader,
        StorageAddress,
        StorageCommitment,
        StorageValue,
        TransactionHash,
        TransactionIndex,
    };
    use pathfinder_crypto::Felt;
    use pathfinder_storage::fake::Block;
    use proptest::prelude::*;
    use tokio::runtime::Runtime;

    use crate::p2p_network::sync_handlers;

    #[macro_export]
    macro_rules! prop_assert_eq_sorted {
        ($left:expr, $right:expr) => {{
            let left = &$left;
            let right = &$right;
            let comparison_string = pretty_assertions_sorted::Comparison::new(
                &pretty_assertions_sorted::SortedDebug::new(left),
                &pretty_assertions_sorted::SortedDebug::new(right)
            ).to_string();
            proptest::prop_assert!(
                *left == *right,
                "assertion failed: `(left == right)`\n{comparison_string}\n");
        }};

        ($left:expr, $right:expr, $fmt:tt $($args:tt)*) => {{
            let left = &$left;
            let right = &$right;
            let comparison_string = pretty_assertions_sorted::Comparison::new(
                &pretty_assertions_sorted::SortedDebug::new(left),
                &pretty_assertions_sorted::SortedDebug::new(right)
            ).to_string();
            proptest::prop_assert!(
                *left == *right,
                concat!(
                    "assertion failed: `(left == right)`\n\
                    {}: ", $fmt),
                comparison_string $($args)*);
        }};
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        #[test]
        fn get_headers((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            // Compute the overlapping set between the db and the request
            // These are the headers that we expect to be read from the db
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction)
                .into_iter().map(|Block { mut header, .. }| {
                    // P2P headers don't carry class commitment and storage commitment, so zero them just like `try_from_dto` does
                    header.header.class_commitment = ClassCommitment::ZERO;
                    header.header.storage_commitment = StorageCommitment::ZERO;
                    header
                }).collect::<Vec<_>>();
            // Run the handler
            let request = BlockHeadersRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let mut responses = Runtime::new().unwrap().block_on(async {
                let (tx, rx) = mpsc::channel(0);
                let getter_fut = sync_handlers::get_headers(storage, request, tx);
                // Waiting for both futures to run to completion is faster than spawning the getter
                // and awaiting the receiver (almost 1s for 100 iterations on Ryzen 3700X).
                // BTW, we cannot just await the getter and then the receiver
                // as there is backpressure (channel size 0) and we would deadlock.
                let (_, response) = tokio::join!(getter_fut, rx.collect::<Vec<_>>());
                response
            });

            // Make sure the last reply is Fin
            assert_eq!(responses.pop().unwrap(), BlockHeadersResponse::Fin);

            // Check the rest
            let actual = responses.into_iter().map(|response| match response {
                BlockHeadersResponse::Header(hdr) => SignedBlockHeader::try_from_dto(*hdr).unwrap(),
                _ => panic!("unexpected response"),
            }).collect::<Vec<_>>();

            prop_assert_eq_sorted!(actual, expected);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        #[test]
        fn get_state_diffs((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            // Compute the overlapping set between the db and the request
            // These are the items that we expect to be read from the db
            // Grouped by block number
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|Block { header, state_update, .. }|
                    (
                        header.header.number, // Block number
                        state_update.contract_updates.into_iter().map(|(k, v)| (k, p2p::client::peer_agnostic::ContractUpdate {
                            storage: v.storage,
                            class: v.class.map(|x| x.class_hash()),
                            nonce: v.nonce,
                        })).collect::<HashMap<_, _>>(),
                        state_update.system_contract_updates,
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = StateDiffsRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let mut responses = Runtime::new().unwrap().block_on(async {
                let (tx, rx) = mpsc::channel(0);
                let getter_fut = sync_handlers::get_state_diffs(storage, request, tx);
                let (_, response) = tokio::join!(getter_fut, rx.collect::<Vec<_>>());
                response
            });

            // Make sure the last reply is Fin
            assert_eq!(responses.pop().unwrap(), StateDiffsResponse::Fin);

            let mut actual_contract_updates = Vec::new();
            let mut actual_system_contract_updates = Vec::new();

            // Check the rest
            responses.into_iter().for_each(|response| match response {
                StateDiffsResponse::ContractDiff(ContractDiff { address, nonce, class_hash, values, domain: _ }) => {
                    if address.0 == Felt::from_u64(1) {
                        actual_system_contract_updates.push(
                            (
                                ContractAddress(address.0),
                                SystemContractUpdate {
                                    storage: values.into_iter().map(
                                        |ContractStoredValue { key, value }| (StorageAddress(key), StorageValue(value))).collect()}
                            ));
                    } else {
                        actual_contract_updates.push(
                            (
                                ContractAddress(address.0),
                                p2p::client::peer_agnostic::ContractUpdate {
                                    storage: values.into_iter().map(|ContractStoredValue { key, value }|
                                        (StorageAddress(key), StorageValue(value))).collect(),
                                    class: class_hash.map(ClassHash),
                                    nonce: nonce.map(ContractNonce)}
                            ));
                    }

                },
                _ => panic!("unexpected response"),
            });

            for expected_for_block in expected {
                let actual_contract_updates_for_block = actual_contract_updates.drain(..expected_for_block.1.len()).collect::<HashMap<_,_>>();
                let actual_system_contract_updates_for_block = actual_system_contract_updates.drain(..expected_for_block.2.len()).collect::<HashMap<_,_>>();
                prop_assert_eq_sorted!(expected_for_block.1, actual_contract_updates_for_block, "block number: {}", expected_for_block.0);
                prop_assert_eq_sorted!(expected_for_block.2, actual_system_contract_updates_for_block, "block number: {}", expected_for_block.0);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(25))]
        #[test]
        fn get_classes((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            // Compute the overlapping set between the db and the request
            // These are the items that we expect to be read from the db
            // Grouped by block number
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|Block { header, cairo_defs, sierra_defs, .. }|
                    (
                        // Block number
                        header.header.number,
                        // List of tuples (Cairo class hash, Cairo definition bytes)
                        cairo_defs,
                        // List of tuples (Sierra class hash, Sierra definition bytes, Casm definition bytes)
                        sierra_defs
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = ClassesRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let mut responses = Runtime::new().unwrap().block_on(async {
                let (tx, rx) = mpsc::channel(0);
                let getter_fut = sync_handlers::get_classes(storage, request, tx);
                let (_, response) = tokio::join!(getter_fut, rx.collect::<Vec<_>>());
                response
            });

            // Make sure the last reply is Fin
            assert_eq!(responses.pop().unwrap(), ClassesResponse::Fin);

            // Check the rest
            let mut actual_cairo = Vec::new();
            let mut actual_sierra = Vec::new();

            responses.into_iter().for_each(|response| match response {
                ClassesResponse::Class(Class::Cairo0 { class, domain: _, class_hash }) => {
                    actual_cairo.push((ClassHash(class_hash.0), CairoDefinition::try_from_dto(class).unwrap().0));
                },
                ClassesResponse::Class(Class::Cairo1 { class, domain: _, class_hash }) => {
                    let SierraDefinition(sierra) = SierraDefinition::try_from_dto(class).unwrap();
                    actual_sierra.push((SierraHash(class_hash.0), sierra, Vec::new() /*TODO*/));
                },
                _ => panic!("unexpected response"),
            });

            for expected_for_block in expected {
                let actual_cairo_for_block = actual_cairo.drain(..expected_for_block.1.len()).collect::<Vec<_>>();
                let actual_sierra_for_block = actual_sierra.drain(..expected_for_block.2.len()).collect::<Vec<_>>();

                prop_assert_eq!(expected_for_block.1, actual_cairo_for_block, "block number: {}", expected_for_block.0);
                prop_assert_eq!(expected_for_block.2, actual_sierra_for_block, "block number: {}", expected_for_block.0);
            }
        }
    }

    mod workaround {
        use pathfinder_common::transaction::{
            EntryPointType,
            InvokeTransactionV0,
            L1HandlerTransaction,
            TransactionVariant,
        };
        use pathfinder_common::TransactionNonce;

        // Align with the deserialization workaround to avoid false negative mismatches
        pub fn for_legacy_l1_handlers(tx: TransactionVariant) -> TransactionVariant {
            match tx {
                TransactionVariant::InvokeV0(InvokeTransactionV0 {
                    entry_point_type: Some(EntryPointType::L1Handler),
                    calldata,
                    sender_address,
                    entry_point_selector,
                    max_fee: _,
                    signature: _,
                }) => TransactionVariant::L1Handler(L1HandlerTransaction {
                    contract_address: sender_address,
                    entry_point_selector,
                    nonce: TransactionNonce::ZERO,
                    calldata,
                }),
                _ => tx,
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        #[test]
        fn get_transactions((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            // Compute the overlapping set between the db and the request
            // These are the transactions that we expect to be read from the db
            // Grouped by block number
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|Block { header, transaction_data, .. }|
                    (
                        // Block number
                        header.header.number,
                        // List of tuples (TransactionVariant, Receipt)
                        transaction_data.into_iter().map(|(t, mut rec, _)| {
                            // P2P transactions don't carry contract transaction hashes
                            let mut txn = workaround::for_legacy_l1_handlers(t.variant);
                            // P2P transactions don't carry contract address, so zero them just like `try_from_dto` does
                            match &mut txn {
                                TransactionVariant::Deploy(x) => x.contract_address = ContractAddress::ZERO,
                                TransactionVariant::DeployAccountV1(x) => x.contract_address = ContractAddress::ZERO,
                                TransactionVariant::DeployAccountV3(x) => x.contract_address = ContractAddress::ZERO,
                                _ => {}
                            };
                            // P2P receipts don't carry transaction index
                            rec.transaction_index = TransactionIndex::new_or_panic(0);
                            // P2P receipts don't carry transaction hashes
                            rec.transaction_hash = TransactionHash::ZERO;
                            (txn, rec)
                        }).collect::<Vec<_>>()
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = TransactionsRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let mut responses = Runtime::new().unwrap().block_on(async {
                let (tx, rx) = mpsc::channel(0);
                let getter_fut = sync_handlers::get_transactions(storage, request, tx);
                let (_, responses) = tokio::join!(getter_fut, rx.collect::<Vec<_>>());
                responses
            });

            // Make sure the last reply is Fin
            assert_eq!(responses.pop().unwrap(), TransactionsResponse::Fin);

            // Check the rest
            let mut actual = responses.into_iter().map(|response| match response {
                TransactionsResponse::TransactionWithReceipt(TransactionWithReceipt { transaction, receipt }) => {
                    (TransactionVariant::try_from_dto(transaction).unwrap(), Receipt::try_from_dto((receipt, TransactionIndex::new_or_panic(0))).unwrap())
                }
                _ => panic!("unexpected response"),
            }).collect::<Vec<_>>();

            for expected_for_block in expected {
                let actual_for_block = actual.drain(..expected_for_block.1.len()).collect::<Vec<_>>();
                prop_assert_eq_sorted!(expected_for_block.1, actual_for_block, "block number: {}", expected_for_block.0);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(50))]
        #[test]
        fn get_events((num_blocks, seed, start_block, limit, step, direction) in strategy::composite()) {
            // Fake storage with a given number of blocks
            let (storage, in_db) = fixtures::storage_with_seed(seed, num_blocks);
            // Compute the overlapping set between the db and the request
            // These are the items that we expect to be read from the db
            // Grouped by block number
            let expected = overlapping::get(in_db, start_block, limit, step, num_blocks, direction).into_iter()
                .map(|Block { header, transaction_data, .. }|
                    (
                        // Block number
                        header.header.number,
                        // List of tuples (Transaction hash, Event)
                        transaction_data.into_iter().flat_map(|(_, r, events)| events.into_iter().map(move |event| (r.transaction_hash, event)))
                            .collect::<Vec<(TransactionHash, Event)>>()
                    )
            ).collect::<Vec<_>>();
            // Run the handler
            let request = EventsRequest { iteration: Iteration { start: BlockNumberOrHash::Number(start_block), limit, step, direction, } };
            let mut responses = Runtime::new().unwrap().block_on(async {
                let (tx, rx) = mpsc::channel(0);
                let getter_fut = sync_handlers::get_events(storage, request, tx);
                let (_, response) = tokio::join!(getter_fut, rx.collect::<Vec<_>>());
                response
            });

            // Make sure the last reply is Fin
            assert_eq!(responses.pop().unwrap(), EventsResponse::Fin);

            // Check the rest
            let mut actual = responses.into_iter().map(|response| match response {
                EventsResponse::Event(event) => (TransactionHash(event.transaction_hash.0), Event::try_from_dto(event).unwrap()),
                _ => panic!("unexpected response"),
            }).collect::<Vec<_>>();

            for expected_for_block in expected {
                let actual_for_block = actual.drain(..expected_for_block.1.len()).collect::<Vec<_>>();
                prop_assert_eq_sorted!(expected_for_block.1, actual_for_block, "block number: {}", expected_for_block.0);
            }
        }
    }

    /// Fixtures for prop tests
    mod fixtures {
        use pathfinder_storage::fake::{with_n_blocks_and_rng, Block};
        use pathfinder_storage::{Storage, StorageBuilder};

        use crate::p2p_network::sync_handlers::MAX_COUNT_IN_TESTS;

        pub const MAX_NUM_BLOCKS: u64 = MAX_COUNT_IN_TESTS * 2;

        pub fn storage_with_seed(seed: u64, num_blocks: u64) -> (Storage, Vec<Block>) {
            use rand::SeedableRng;
            let storage = StorageBuilder::in_memory().unwrap();
            // Explicitly choose RNG to make sure seeded storage is always reproducible
            let mut rng = rand_chacha::ChaCha12Rng::seed_from_u64(seed);
            let initializer =
                with_n_blocks_and_rng(&storage, num_blocks.try_into().unwrap(), &mut rng);
            (storage, initializer)
        }
    }

    /// Find overlapping range between the DB and the request
    mod overlapping {
        use p2p_proto::common::{Direction, Step};
        use pathfinder_storage::fake::Block;

        use crate::p2p_network::sync_handlers::MAX_COUNT_IN_TESTS;

        pub fn get(
            from_db: Vec<Block>,
            start_block: u64,
            limit: u64,
            step: Step,
            num_blocks: u64,
            direction: Direction,
        ) -> Vec<Block> {
            match direction {
                Direction::Forward => forward(from_db, start_block, limit, step).collect(),
                Direction::Backward => {
                    backward(from_db, start_block, limit, step, num_blocks).collect()
                }
            }
        }

        fn forward(
            from_db: Vec<Block>,
            start_block: u64,
            limit: u64,
            step: Step,
        ) -> impl Iterator<Item = Block> {
            from_db
                .into_iter()
                .skip(start_block.try_into().unwrap())
                .step_by(step.into_inner().try_into().unwrap())
                .take(std::cmp::min(limit, MAX_COUNT_IN_TESTS).try_into().unwrap())
        }

        fn backward(
            mut from_db: Vec<Block>,
            start_block: u64,
            limit: u64,
            step: Step,
            num_blocks: u64,
        ) -> impl Iterator<Item = Block> {
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

    /// Building blocks for the ultimate composite strategy used in all property
    /// tests
    mod strategy {
        use std::ops::Range;

        use p2p_proto::common::{Direction, Step};
        use proptest::prelude::*;

        use super::fixtures::MAX_NUM_BLOCKS;
        use crate::p2p_network::sync_handlers::tests::I64_MAX;

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
