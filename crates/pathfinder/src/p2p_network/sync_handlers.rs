//! Sync related data retrieval from storage as requested by other p2p clients
use anyhow::Context;
use p2p_proto as proto;
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use pathfinder_storage::{Storage, Transaction, V03KeyFilter};

#[cfg(not(test))]
const MAX_HEADERS_COUNT: u64 = 1000;
#[cfg(not(test))]
const MAX_BODIES_COUNT: u64 = 100;
#[cfg(not(test))]
const MAX_STATE_UPDATES_COUNT: u64 = 100;

#[cfg(test)]
const MAX_COUNT_IN_TESTS: u64 = 10;
#[cfg(test)]
const MAX_HEADERS_COUNT: u64 = MAX_COUNT_IN_TESTS;
#[cfg(test)]
const MAX_BODIES_COUNT: u64 = MAX_COUNT_IN_TESTS;
#[cfg(test)]
const MAX_STATE_UPDATES_COUNT: u64 = MAX_COUNT_IN_TESTS;

pub async fn get_block_headers(
    request: p2p_proto::sync::GetBlockHeaders,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockHeaders> {
    spawn_blocking_get(request, storage, block_headers).await
}

pub async fn get_block_bodies(
    request: p2p_proto::sync::GetBlockBodies,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::BlockBodies> {
    spawn_blocking_get(request, storage, block_bodies).await
}

pub async fn get_state_diffs(
    request: p2p_proto::sync::GetStateDiffs,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::StateDiffs> {
    spawn_blocking_get(request, storage, state_diffs).await
}

pub async fn get_classes(
    request: p2p_proto::sync::GetClasses,
    storage: &Storage,
) -> anyhow::Result<p2p_proto::sync::Classes> {
    spawn_blocking_get(request, storage, classes).await
}

async fn spawn_blocking_get<Request, Response, Getter>(
    request: Request,
    storage: &Storage,
    getter: Getter,
) -> anyhow::Result<Response>
where
    Request: Send + 'static,
    Response: Send + 'static,
    Getter: FnOnce(Transaction<'_>, Request) -> anyhow::Result<Response> + Send + 'static,
{
    let storage = storage.clone();
    let span = tracing::Span::current();

    tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut connection = storage
            .connection()
            .context("Opening database connection")?;
        let tx = connection
            .transaction()
            .context("Creating database transaction")?;
        getter(tx, request)
    })
    .await
    .context("Database read panic or shutting down")?
}

fn block_headers(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetBlockHeaders,
) -> anyhow::Result<p2p_proto::sync::BlockHeaders> {
    let mut count = std::cmp::min(request.count, MAX_HEADERS_COUNT);
    let mut headers = Vec::new();

    let mut next_block_number = match BlockNumber::new(request.start_block) {
        Some(n) => Some(n),
        None => anyhow::bail!(
            "Unsupported block number value: {} > i64::MAX",
            request.start_block
        ),
    };

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(header) = tx.block_header(block_number.into())? else {
            // No such block
            break;
        };

        let transaction_count = tx
            .transaction_count(block_number.into())?
            .try_into()
            .context("Number of transactions exceeds 32 bits")?;

        // TODO check if there are faster ways to do this
        let event_count = tx.event_count(
            block_number.into(),
            block_number.into(),
            None,
            &V03KeyFilter::new(vec![]),
        )?;

        headers.push(conv::header::from(
            header,
            transaction_count,
            event_count.try_into()?,
        ));

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto::sync::BlockHeaders { headers })
}

fn block_bodies(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetBlockBodies,
) -> anyhow::Result<p2p_proto::sync::BlockBodies> {
    let mut count = std::cmp::min(request.count, MAX_BODIES_COUNT);
    let mut block_bodies = Vec::new();

    let mut next_block_number = tx
        .block_id(BlockHash(request.start_block).into())?
        .map(|(n, _)| n);

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let transactions_and_receipts = match tx.transaction_data_for_block(block_number.into())? {
            Some(x) if !x.is_empty() => x,
            // No such block
            Some(_) | None => break,
        };

        let (transactions, receipts) = transactions_and_receipts
            .into_iter()
            .map(conv::body::from)
            .unzip();

        block_bodies.push(p2p_proto::common::BlockBody {
            transactions,
            receipts,
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto::sync::BlockBodies { block_bodies })
}

fn state_diffs(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetStateDiffs,
) -> anyhow::Result<p2p_proto::sync::StateDiffs> {
    let mut count = std::cmp::min(request.count, MAX_STATE_UPDATES_COUNT);
    let mut block_state_updates = Vec::new();

    let mut next_block_number = tx
        .block_id(BlockHash(request.start_block).into())?
        .map(|(n, _)| n);

    while let Some(block_number) = next_block_number {
        if count == 0 {
            break;
        }

        let Some(state_update) = tx.state_update(block_number.into())? else {
            // No such state update, shouldn't happen with a single source of truth in L2...
            break;
        };

        block_state_updates.push(p2p_proto::sync::BlockStateUpdateWithHash {
            block_hash: state_update.block_hash.0,
            state_commitment: state_update.state_commitment.0,
            parent_state_commitment: state_update.parent_state_commitment.0,
            state_update: conv::state_update::from(state_update),
        });

        count -= 1;
        next_block_number = get_next_block_number(block_number, request.direction);
    }

    Ok(p2p_proto::sync::StateDiffs {
        block_state_updates,
    })
}

fn classes(
    tx: Transaction<'_>,
    request: p2p_proto::sync::GetClasses,
) -> anyhow::Result<p2p_proto::sync::Classes> {
    let mut classes = Vec::new();
    for hash in request.class_hashes {
        let Some(class) = tx.class_definition(ClassHash(hash))? else {
            break;
        };

        classes.push(p2p_proto::common::RawClass { class });
    }

    Ok(p2p_proto::sync::Classes { classes })
}

/// Workaround for the orphan rule - implement conversion fns for types ourside our crate.
mod conv {
    pub(super) mod header {
        use pathfinder_common::BlockHeader;

        pub fn from(
            header: BlockHeader,
            transaction_count: u32,
            event_count: u32,
        ) -> p2p_proto::common::BlockHeader {
            p2p_proto::common::BlockHeader {
                hash: header.hash.0,
                parent_hash: header.parent_hash.0,
                number: header.number.get(),
                state_commitment: header.state_commitment.0,
                storage_commitment: header.storage_commitment.0,
                class_commitment: header.class_commitment.0,
                sequencer_address: header.sequencer_address.0,
                timestamp: header.timestamp.get(),
                gas_price: header.gas_price.0.into(),
                transaction_count,
                transaction_commitment: header.transaction_commitment.0,
                event_count,
                event_commitment: header.event_commitment.0,
                starknet_version: header.starknet_version.take_inner(),
            }
        }
    }

    pub(super) mod body {
        use p2p_proto::common::{
            execution_resources::BuiltinInstanceCounter, invoke_transaction::EntryPoint,
            CommonTransactionReceiptProperties, DeclareTransaction, DeclareTransactionReceipt,
            DeployAccountTransaction, DeployAccountTransactionReceipt, DeployTransaction,
            DeployTransactionReceipt, Event, ExecutionResources, InvokeTransaction,
            InvokeTransactionReceipt, MessageToL1, MessageToL2, Receipt, Transaction,
        };
        use pathfinder_common::{Fee, L1ToL2MessageNonce, TransactionNonce};
        use stark_hash::Felt;
        use starknet_gateway_types::reply::transaction as gw;

        pub fn from((gw_t, gw_r): (gw::Transaction, gw::Receipt)) -> (Transaction, Receipt) {
            let common = CommonTransactionReceiptProperties {
                transaction_hash: gw_t.hash().0,
                transaction_index: gw_r
                    .transaction_index
                    .get()
                    .try_into()
                    .expect("Transaction index fits in 32 bits"),
                actual_fee: gw_r.actual_fee.unwrap_or(Fee::ZERO).0,
                messages_sent: gw_r
                    .l2_to_l1_messages
                    .into_iter()
                    .map(|m| MessageToL1 {
                        from_address: *m.from_address.get(),
                        payload: m.payload.into_iter().map(|x| x.0).collect(),
                        to_address: m.to_address.0,
                    })
                    .collect(),
                events: gw_r
                    .events
                    .into_iter()
                    .map(|e| Event {
                        from_address: *e.from_address.get(),
                        keys: e.keys.into_iter().map(|k| k.0).collect(),
                        data: e.data.into_iter().map(|d| d.0).collect(),
                    })
                    .collect(),
                consumed_message: gw_r.l1_to_l2_consumed_message.map(|x| MessageToL2 {
                    from_address: x.from_address.0,
                    payload: x.payload.into_iter().map(|e| e.0).collect(),
                    to_address: *x.to_address.get(),
                    entry_point_selector: x.selector.0,
                    nonce: x.nonce.unwrap_or(L1ToL2MessageNonce::ZERO).0,
                }),
                execution_resources: {
                    let x = gw_r.execution_resources.unwrap_or_default();
                    let b = x.builtin_instance_counter;
                    ExecutionResources {
                        builtin_instance_counter: BuiltinInstanceCounter {
                            bitwise_builtin: b.bitwise_builtin,
                            ecdsa_builtin: b.ecdsa_builtin,
                            ec_op_builtin: b.ec_op_builtin,
                            output_builtin: b.output_builtin,
                            pedersen_builtin: b.pedersen_builtin,
                            range_check_builtin: b.range_check_builtin,
                        },
                        n_steps: x.n_steps,
                        n_memory_holes: x.n_memory_holes,
                    }
                },
            };

            let version = Felt::from_be_slice(gw_t.version().0.as_bytes())
                .expect("Transaction version fits into felt");

            match gw_t {
                gw::Transaction::Declare(
                    gw::DeclareTransaction::V0(t) | gw::DeclareTransaction::V1(t),
                ) => {
                    let r = Receipt::Declare(DeclareTransactionReceipt { common });
                    let t = Transaction::Declare(DeclareTransaction {
                        class_hash: t.class_hash.0,
                        sender_address: *t.sender_address.get(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        version,
                        casm_hash: Felt::ZERO,
                    });
                    (t, r)
                }
                gw::Transaction::Declare(gw::DeclareTransaction::V2(t)) => {
                    let r = Receipt::Declare(DeclareTransactionReceipt { common });
                    let t = Transaction::Declare(DeclareTransaction {
                        class_hash: t.class_hash.0,
                        sender_address: *t.sender_address.get(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        version,
                        casm_hash: t.compiled_class_hash.0,
                    });
                    (t, r)
                }
                gw::Transaction::Deploy(t) => {
                    let r = Receipt::Deploy(DeployTransactionReceipt {
                        common,
                        contract_address: *t.contract_address.get(),
                    });
                    let t = Transaction::Deploy(DeployTransaction {
                        class_hash: t.class_hash.0,
                        contract_address_salt: t.contract_address_salt.0,
                        constructor_calldata: t
                            .constructor_calldata
                            .into_iter()
                            .map(|x| x.0)
                            .collect(),
                        version,
                    });
                    (t, r)
                }
                gw::Transaction::DeployAccount(t) => {
                    let r = Receipt::DeployAccount(DeployAccountTransactionReceipt {
                        common,
                        contract_address: *t.contract_address.get(),
                    });
                    let t = Transaction::DeployAccount(DeployAccountTransaction {
                        class_hash: t.class_hash.0,
                        contract_address_salt: t.contract_address_salt.0,
                        constructor_calldata: t
                            .constructor_calldata
                            .into_iter()
                            .map(|x| x.0)
                            .collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        version,
                    });
                    (t, r)
                }
                gw::Transaction::Invoke(gw::InvokeTransaction::V0(t)) => {
                    let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                    let t = Transaction::Invoke(InvokeTransaction {
                        sender_address: *t.sender_address.get(),
                        deprecated_entry_point_selector: match t.entry_point_type {
                            Some(gw::EntryPointType::External) => {
                                Some(EntryPoint::External(t.entry_point_selector.0))
                            }
                            Some(gw::EntryPointType::L1Handler) => {
                                Some(EntryPoint::L1Handler(t.entry_point_selector.0))
                            }
                            None => Some(EntryPoint::Unspecified(t.entry_point_selector.0)),
                        },
                        calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: TransactionNonce::ZERO.0,
                        version,
                    });
                    (t, r)
                }
                gw::Transaction::Invoke(gw::InvokeTransaction::V1(t)) => {
                    let r = Receipt::Invoke(InvokeTransactionReceipt { common });
                    let t = Transaction::Invoke(InvokeTransaction {
                        sender_address: *t.sender_address.get(),
                        deprecated_entry_point_selector: None,
                        calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                        signature: t.signature.into_iter().map(|x| x.0).collect(),
                        max_fee: t.max_fee.0,
                        nonce: t.nonce.0,
                        version,
                    });
                    (t, r)
                }
                gw::Transaction::L1Handler(t) => {
                    let r = Receipt::L1Handler(p2p_proto::common::L1HandlerTransactionReceipt {
                        common,
                    });
                    let t = Transaction::L1Handler(p2p_proto::common::L1HandlerTransaction {
                        contract_address: *t.contract_address.get(),
                        entry_point_selector: t.entry_point_selector.0,
                        calldata: t.calldata.into_iter().map(|x| x.0).collect(),
                        nonce: t.nonce.0,
                        version,
                    });
                    (t, r)
                }
            }
        }
    }

    pub(super) mod state_update {
        use p2p_proto::propagation::{
            BlockStateUpdate, ContractDiff, DeclaredClass, DeployedContract, ReplacedClass,
            StorageDiff,
        };
        use pathfinder_common::{
            state_update::{ContractClassUpdate, StateUpdate},
            ContractNonce,
        };

        pub fn from(x: StateUpdate) -> BlockStateUpdate {
            let mut deployed_contracts = Vec::new();
            let mut replaced_classes = Vec::new();
            let contract_diffs =
                x.contract_updates
                    .into_iter()
                    .map(|(contract_address, update)| {
                        let nonce = update.nonce.unwrap_or_default().0;
                        let storage_diffs = update
                            .storage
                            .into_iter()
                            .map(|(key, value)| StorageDiff {
                                key: key.0,
                                value: value.0,
                            })
                            .collect();
                        match update.class {
                            Some(ContractClassUpdate::Deploy(class_hash)) => deployed_contracts
                                .push(DeployedContract {
                                    contract_address: contract_address.0,
                                    class_hash: class_hash.0,
                                }),
                            Some(ContractClassUpdate::Replace(class_hash)) => replaced_classes
                                .push(ReplacedClass {
                                    contract_address: contract_address.0,
                                    class_hash: class_hash.0,
                                }),
                            None => {}
                        }

                        ContractDiff {
                            contract_address: contract_address.0,
                            nonce,
                            storage_diffs,
                        }
                    })
                    .chain(x.system_contract_updates.into_iter().map(
                        |(contract_address, update)| {
                            let storage_diffs = update
                                .storage
                                .into_iter()
                                .map(|(key, value)| StorageDiff {
                                    key: key.0,
                                    value: value.0,
                                })
                                .collect();
                            ContractDiff {
                                contract_address: contract_address.0,
                                nonce: ContractNonce::ZERO.0,
                                storage_diffs,
                            }
                        },
                    ))
                    .collect();

            BlockStateUpdate {
                contract_diffs,
                deployed_contracts,
                declared_cairo_classes: x.declared_cairo_classes.into_iter().map(|c| c.0).collect(),
                declared_classes: x
                    .declared_sierra_classes
                    .into_iter()
                    .map(|(sierra_hash, casm_hash)| DeclaredClass {
                        sierra_hash: sierra_hash.0,
                        casm_hash: casm_hash.0,
                    })
                    .collect(),
                replaced_classes,
            }
        }
    }
}

/// Returns next block number considering direction.
///
/// None is returned if we're out-of-bounds.
fn get_next_block_number(
    current: BlockNumber,
    direction: proto::sync::Direction,
) -> Option<BlockNumber> {
    match direction {
        proto::sync::Direction::Forward => current.get().checked_add(1).and_then(BlockNumber::new),
        proto::sync::Direction::Backward => current.get().checked_sub(1).and_then(BlockNumber::new),
    }
}

#[cfg(test)]
mod tests {
    use super::{block_bodies, block_headers, state_diffs};
    use assert_matches::assert_matches;
    use fake::{Fake, Faker};
    use p2p_proto::sync::{
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
        request: p2p_proto::sync::Request,
    ) -> anyhow::Result<p2p_proto::sync::Response> {
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
        let request = p2p_proto::sync::GetBlockHeaders {
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
            use crate::p2p_network::client::conv::header;
            use proptest::prelude::*;

            proptest! {
                #[test]
                fn forward((start, count, seed, num_blocks) in super::strategy::forward()) {
                    // Initialize storage once for this proptest, greatly increases performance
                    let (storage, from_db) = storage_with_seed(seed, num_blocks);

                    let from_db = overlapping::forward(from_db, start, count).map(|(header, _, _)| header).collect::<Vec<_>>();

                    let request = p2p_proto::sync::GetBlockHeaders {
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

                    let request = p2p_proto::sync::GetBlockHeaders {
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
            use crate::p2p_network::client::conv::body;
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
                // FIXME: unignore once reverted is supported
                #[test]
                #[ignore]
                fn forward((start, count, seed, num_blocks) in super::strategy::forward()) {
                    // Initialize storage once for this proptest, greatly increases performance
                    // static STORAGE: SeededStorage = OnceCell::new();
                    // let (storage, from_db) = STORAGE.get_or_init(|| {storage_with_seed(seed)}).clone();
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

                    let request = p2p_proto::sync::GetBlockBodies {
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

                // FIXME: unignore once reverted is supported
                #[test]
                #[ignore]
                fn backward((start, count, seed, num_blocks) in super::strategy::backward()) {
                    // Initialize storage once for this proptest, greatly increases performance
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

                    let request = p2p_proto::sync::GetBlockBodies {
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
            use crate::p2p_network::client::conv::state_update;
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

                    let request = p2p_proto::sync::GetStateDiffs {
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

                    let request = p2p_proto::sync::GetStateDiffs {
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
}
