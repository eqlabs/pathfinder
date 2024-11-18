//! Create fake blockchain data for test purposes
use fake::{Fake, Faker};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::StateUpdateRef;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{
    BlockHash,
    BlockHeader,
    BlockNumber,
    ClassCommitment,
    ClassHash,
    EventCommitment,
    ReceiptCommitment,
    SierraHash,
    SignedBlockHeader,
    StarknetVersion,
    StateCommitment,
    StateUpdate,
    StorageCommitment,
    TransactionCommitment,
    TransactionHash,
};
use rand::Rng;

use crate::Storage;

// TODO merge the apis, hide the init api, leave a storage filler api, remove
// unused apis

// Summary [ 157.075s] 1099 tests run: 1097 passed (4 slow), 2 failed, 22
// skipped FAIL [ 156.606s] pathfinder
// p2p_network::sync_handlers::tests::prop::get_classes FAIL [   0.146s]
// pathfinder-rpc
// method::subscribe_transaction_status::tests::transaction_status_streaming

pub type ModifyStorageFn = Box<dyn Fn(&mut [Block])>;
pub type BlockHashFn = Box<dyn Fn(&BlockHeader) -> BlockHash>;
pub type TransactionCommitmentFn =
    Box<dyn Fn(&[Transaction], StarknetVersion) -> anyhow::Result<TransactionCommitment>>;
pub type ReceiptCommitmentFn = Box<dyn Fn(&[Receipt]) -> anyhow::Result<ReceiptCommitment>>;
pub type EventCommitmentFn =
    Box<dyn Fn(&[(TransactionHash, &[Event])], StarknetVersion) -> anyhow::Result<EventCommitment>>;
pub type UpdateTriesFn = Box<
    dyn Fn(
        &crate::Transaction<'_>,
        StateUpdateRef<'_>,
        bool,
        BlockNumber,
        Storage,
    ) -> anyhow::Result<(StorageCommitment, ClassCommitment)>,
>;

pub struct Config {
    pub calculate_block_hash: BlockHashFn,
    pub calculate_transaction_commitment: TransactionCommitmentFn,
    pub calculate_receipt_commitment: ReceiptCommitmentFn,
    pub calculate_event_commitment: EventCommitmentFn,
    pub update_tries: UpdateTriesFn,
    /// This function is called after the blocks are generated and after all the
    /// commitments and hashes are calculated but before the data is inserted
    /// into the db.
    pub modify_storage: ModifyStorageFn,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            calculate_block_hash: Box::new(|_| Faker.fake()),
            calculate_transaction_commitment: Box::new(|_, _| Ok(Faker.fake())),
            calculate_receipt_commitment: Box::new(|_| Ok(Faker.fake())),
            calculate_event_commitment: Box::new(|_, _| Ok(Faker.fake())),
            update_tries: Box::new(|_, _, _, _, _| Ok((Faker.fake(), Faker.fake()))),
            modify_storage: Box::new(|_| {}),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Block {
    pub header: SignedBlockHeader,
    pub transaction_data: Vec<(Transaction, Receipt, Vec<Event>)>,
    pub state_update: StateUpdate, // TODO make it StateUpdateData
    pub cairo_defs: Vec<(ClassHash, Vec<u8>)>, // Cairo 0 definitions
    pub sierra_defs: Vec<(SierraHash, Vec<u8>, Vec<u8>)>, // Sierra + Casm definitions
}

/// Initialize [`Storage`] with fake blocks and state updates
/// maintaining [**limited consistency
/// guarantees**](crate::fake::init::with_n_blocks)
pub fn with_n_blocks(storage: &Storage, n: usize) -> Vec<Block> {
    let mut rng = rand::thread_rng();
    with_n_blocks_and_rng(storage, n, &mut rng)
}

/// Inserts trie data into the DB and updates headers with computed commitments.
pub fn insert_tries(
    db: &crate::Transaction<'_>,
    storage: Storage,
    blocks: &mut [Block],
    update_tries: UpdateTriesFn,
) {
    blocks.iter_mut().for_each(
        |Block {
             header,
             state_update,
             ..
         }| {
            let (storage_commitment, class_commitment) = update_tries(
                &db,
                state_update.into(),
                false,
                header.header.number,
                storage.clone(),
            )
            .unwrap();

            let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
            header.header.storage_commitment = storage_commitment;
            header.header.class_commitment = class_commitment;
            header.header.state_commitment = state_commitment;
        },
    );
}

/// Initialize [`Storage`] with a slice of already generated blocks
pub fn fill_with_config2(
    storage: &Storage,
    blocks: &[Block],
    update_tries: UpdateTriesFn,
) -> Vec<(StorageCommitment, ClassCommitment)> {
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    let mut computed_commitments = Vec::with_capacity(blocks.len());

    blocks.iter().for_each(
        |Block {
             header,
             transaction_data,
             state_update,
             cairo_defs,
             sierra_defs,
             ..
         }| {
            tx.insert_block_header(&header.header).unwrap();
            tx.insert_signature(header.header.number, &header.signature)
                .unwrap();
            tx.insert_transaction_data(
                header.header.number,
                &transaction_data
                    .iter()
                    .cloned()
                    .map(|(tx, receipt, ..)| (tx, receipt))
                    .collect::<Vec<_>>(),
                Some(
                    &transaction_data
                        .iter()
                        .cloned()
                        .map(|(_, _, events)| events)
                        .collect::<Vec<_>>(),
                ),
            )
            .unwrap();

            let (storage_commitment, class_commitment) = update_tries(
                &tx,
                state_update.into(),
                false,
                header.header.number,
                storage.clone(),
            )
            .unwrap();

            computed_commitments.push((storage_commitment, class_commitment));

            tx.update_storage_and_class_commitments(
                header.header.number,
                storage_commitment,
                class_commitment,
            )
            .unwrap();

            // TODO insert_state_update_data
            tx.insert_state_update(header.header.number, state_update)
                .unwrap();

            cairo_defs.iter().for_each(|(cairo_hash, definition)| {
                tx.insert_cairo_class(*cairo_hash, definition).unwrap()
            });

            sierra_defs
                .iter()
                .for_each(|(sierra_hash, sierra_definition, casm_definition)| {
                    tx.insert_sierra_class(
                        sierra_hash,
                        sierra_definition,
                        state_update
                            .declared_sierra_classes
                            .get(sierra_hash)
                            .unwrap(),
                        casm_definition,
                    )
                    .unwrap()
                });
        },
    );
    tx.commit().unwrap();

    computed_commitments
}

/// Initialize [`Storage`] with a slice of already generated blocks
pub fn fill(storage: &Storage, blocks: &[Block]) {
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    blocks.iter().for_each(
        |Block {
             header,
             transaction_data,
             state_update,
             cairo_defs,
             sierra_defs,
             ..
         }| {
            tx.insert_block_header(&header.header).unwrap();
            tx.insert_signature(header.header.number, &header.signature)
                .unwrap();
            tx.insert_transaction_data(
                header.header.number,
                &transaction_data
                    .iter()
                    .cloned()
                    .map(|(tx, receipt, ..)| (tx, receipt))
                    .collect::<Vec<_>>(),
                Some(
                    &transaction_data
                        .iter()
                        .cloned()
                        .map(|(_, _, events)| events)
                        .collect::<Vec<_>>(),
                ),
            )
            .unwrap();

            // let (storage_commitment, class_commitment) = update_starknet_state(
            //     &db,
            //     (&state_diff).into(),
            //     self.verify_tree_hashes,
            //     block_number,
            //     self.storage.clone(),
            // )
            // .unwrap();

            // db.update_storage_and_class_commitments(
            //     block_number,
            //     storage_commitment,
            //     class_commitment,
            // )
            // .context("Updating storage and class commitments")?;
            // db.insert_state_update_data(block_number, &state_diff)
            //     .context("Inserting state update data")?;

            // TODO insert_state_update_data
            tx.insert_state_update(header.header.number, state_update)
                .unwrap();

            cairo_defs.iter().for_each(|(cairo_hash, definition)| {
                tx.insert_cairo_class(*cairo_hash, definition).unwrap()
            });

            sierra_defs
                .iter()
                .for_each(|(sierra_hash, sierra_definition, casm_definition)| {
                    tx.insert_sierra_class(
                        sierra_hash,
                        sierra_definition,
                        state_update
                            .declared_sierra_classes
                            .get(sierra_hash)
                            .unwrap(),
                        casm_definition,
                    )
                    .unwrap()
                });
        },
    );
    tx.commit().unwrap();
}

/// Same as [`with_n_blocks`] except caller can specify the rng used
pub fn with_n_blocks_and_rng<R: Rng>(storage: &Storage, n: usize, rng: &mut R) -> Vec<Block> {
    let blocks = init::with_n_blocks_and_rng(n, rng);
    fill(storage, &blocks);
    blocks
}

/// Same as [`with_n_blocks`] except caller can specify the rng and additional
/// configuration
pub fn with_n_blocks_rng_and_config<R: Rng>(
    storage: &Storage,
    n: usize,
    rng: &mut R,
    config: init::Config,
) -> Vec<Block> {
    let blocks = init::with_n_blocks_rng_and_config(n, rng, config);
    fill(storage, &blocks);
    blocks
}

/// ### Important
///
/// Returns a tuple of `(inserted_blocks, generated_blocks)` where the latter
/// are the fake blocks that were generated, and the former and the generated
/// blocks after applying [`Config::modify_storage`].
pub fn with_n_blocks_rng_and_config2<R: Rng>(
    storage: &Storage,
    n: usize,
    rng: &mut R,
    config: Config,
) -> (Vec<Block>, Vec<Block>) {
    let Config {
        calculate_block_hash,
        calculate_transaction_commitment,
        calculate_receipt_commitment,
        calculate_event_commitment,
        update_tries,
        modify_storage,
    } = config;
    // Generate some fake blocks
    let mut blocks = init::with_n_blocks_rng_and_config(
        n,
        rng,
        init::Config {
            calculate_transaction_commitment,
            calculate_receipt_commitment,
            calculate_event_commitment,
        },
    );

    let mut db = storage.connection().unwrap();
    let db = db.transaction().unwrap();
    // Tries go into the DB first, headers are updated with the computed commitments
    insert_tries(&db, storage.clone(), &mut blocks, update_tries);
    // Block hashes can be computed now
    compute_block_hashes(&mut blocks, calculate_block_hash);
    let mut inserted_blocks = blocks.clone();
    // Apply additional modifications
    modify_storage(&mut inserted_blocks);
    // All the block data is inserted into the DB
    fill_block_data(&db, &inserted_blocks);

    db.commit().unwrap();

    (inserted_blocks, blocks)
}

// Computes block hashes, updates parent block hashes with the correct values
fn compute_block_hashes(blocks: &mut [Block], calculate_block_hash: BlockHashFn) {
    let Block {
        header,
        state_update,
        ..
    } = blocks.get_mut(0).unwrap();
    header.header.parent_hash = BlockHash::ZERO;
    header.header.hash = calculate_block_hash(&header.header);
    state_update.block_hash = header.header.hash;

    for i in 1..blocks.len() {
        let parent_hash = blocks
            .get(i - 1)
            .map(|Block { header, .. }| header.header.hash)
            .unwrap();
        let Block {
            header,
            state_update,
            ..
        } = blocks.get_mut(i).unwrap();

        header.header.parent_hash = parent_hash;
        header.header.hash = calculate_block_hash(&header.header);
        state_update.block_hash = header.header.hash;
    }
}

pub fn fill_block_data(db: &crate::Transaction<'_>, blocks: &[Block]) {
    blocks.iter().for_each(
        |Block {
             header,
             transaction_data,
             state_update,
             cairo_defs,
             sierra_defs,
             ..
         }| {
            db.insert_block_header(&header.header).unwrap();
            db.insert_signature(header.header.number, &header.signature)
                .unwrap();
            db.insert_transaction_data(
                header.header.number,
                &transaction_data
                    .iter()
                    .cloned()
                    .map(|(tx, receipt, ..)| (tx, receipt))
                    .collect::<Vec<_>>(),
                Some(
                    &transaction_data
                        .iter()
                        .cloned()
                        .map(|(_, _, events)| events)
                        .collect::<Vec<_>>(),
                ),
            )
            .unwrap();

            // TODO insert_state_update_data
            db.insert_state_update(header.header.number, state_update)
                .unwrap();

            cairo_defs.iter().for_each(|(cairo_hash, definition)| {
                db.insert_cairo_class(*cairo_hash, definition).unwrap()
            });

            sierra_defs
                .iter()
                .for_each(|(sierra_hash, sierra_definition, casm_definition)| {
                    db.insert_sierra_class(
                        sierra_hash,
                        sierra_definition,
                        state_update
                            .declared_sierra_classes
                            .get(sierra_hash)
                            .unwrap(),
                        casm_definition,
                    )
                    .unwrap()
                });
        },
    );
}

/// TODO
pub fn with_n_blocks_and_config2(
    storage: &Storage,
    n: usize,
    config: Config,
) -> (Vec<Block>, Vec<Block>) {
    let mut rng = rand::thread_rng();
    with_n_blocks_rng_and_config2(storage, n, &mut rng, config)
}

/// Raw _fake state initializers_
mod init {
    use std::collections::{HashMap, HashSet};

    use fake::{Fake, Faker};
    use pathfinder_common::event::Event;
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::state_update::{
        ContractClassUpdate,
        ContractUpdate,
        SystemContractUpdate,
    };
    use pathfinder_common::test_utils::fake_non_empty_with_rng;
    use pathfinder_common::transaction::Transaction;
    use pathfinder_common::{
        class_definition,
        BlockHash,
        BlockHeader,
        BlockNumber,
        ChainId,
        ClassHash,
        ContractAddress,
        EventCommitment,
        ReceiptCommitment,
        SierraHash,
        SignedBlockHeader,
        StarknetVersion,
        StateCommitment,
        StateUpdate,
        TransactionCommitment,
        TransactionHash,
        TransactionIndex,
    };
    use rand::seq::IteratorRandom;
    use rand::Rng;
    use starknet_gateway_types::class_hash::compute_class_hash;

    use super::Block;

    pub type TransactionCommitmentFn =
        Box<dyn Fn(&[Transaction], StarknetVersion) -> anyhow::Result<TransactionCommitment>>;
    pub type ReceiptCommitmentFn = Box<dyn Fn(&[Receipt]) -> anyhow::Result<ReceiptCommitment>>;
    pub type EventCommitmentFn = Box<
        dyn Fn(&[(TransactionHash, &[Event])], StarknetVersion) -> anyhow::Result<EventCommitment>,
    >;

    pub struct Config {
        pub calculate_transaction_commitment: TransactionCommitmentFn,
        pub calculate_receipt_commitment: ReceiptCommitmentFn,
        pub calculate_event_commitment: EventCommitmentFn,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                calculate_transaction_commitment: Box::new(|_, _| Ok(Faker.fake())),
                calculate_receipt_commitment: Box::new(|_| Ok(Faker.fake())),
                calculate_event_commitment: Box::new(|_, _| Ok(Faker.fake())),
            }
        }
    }

    /// Create fake blocks and state updates with __limited consistency
    /// guarantees__:
    /// - starknet version: 0.13.2
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, parent hash of the genesis block
    ///       is `0`
    ///     - state commitment is a hash of storage and class commitments
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    ///     - at least 1 transaction with receipt per block
    /// - state updates:
    ///     - block hashes
    ///     - parent state commitment wrt previous state update, parent state
    ///       commitment of the genesis state update is `0`
    ///     - old roots wrt previous state update, old root of the genesis state
    ///       update is `0`
    ///     - replaced classes for block N point to some deployed contracts from
    ///       block N-1
    ///     - each storage diff has its respective nonce update
    ///     - storage entries constrain at least 1 element
    ///     - deployed Cairo0 contracts are treated as implicit declarations and
    ///       are added to declared cairo classes`
    /// - declared cairo|sierra definitions
    ///     - class definition is a serialized to JSON representation of
    ///       `class_definition::Cairo|Sierra` respectively with random fields
    ///     - all those definitions are **very short and fall far below the soft
    ///       limit in protobuf encoding
    ///     - casm definitions for sierra classes are purely random Strings
    ///     - cairo class hashes and sierra class hashes are correctly
    ///       calculated from the definitions, casm hashes are random
    /// - transactions
    ///     - transaction hashes are calculated from their respective variant,
    ///       with ChainId set to `SEPOLIA_TESTNET`
    pub fn with_n_blocks(n: usize) -> Vec<Block> {
        let mut rng = rand::thread_rng();
        with_n_blocks_and_rng(n, &mut rng)
    }

    /// Same as [`with_n_blocks`] except caller can specify additional
    /// configuration
    pub fn with_n_blocks_and_config(n: usize, config: Config) -> Vec<Block> {
        let mut rng = rand::thread_rng();
        with_n_blocks_rng_and_config(n, &mut rng, config)
    }

    /// Same as [`with_n_blocks`] except caller can specify the rng used
    pub fn with_n_blocks_and_rng<R: Rng>(n: usize, rng: &mut R) -> Vec<Block> {
        with_n_blocks_rng_and_config(n, rng, Default::default())
    }

    /// Same as [`with_n_blocks`] except caller can specify the rng used and
    /// additional configuration
    pub fn with_n_blocks_rng_and_config<R: Rng>(
        n: usize,
        rng: &mut R,
        config: Config,
    ) -> Vec<Block> {
        let mut init = Vec::with_capacity(n);
        let mut declared_classes_accum = HashSet::new();

        for i in 0..n {
            let mut header: BlockHeader = Faker.fake_with_rng(rng);
            header.starknet_version = StarknetVersion::V_0_13_2;
            header.number =
                BlockNumber::new_or_panic(i.try_into().expect("u64 is at least as wide as usize"));
            header.state_commitment =
                StateCommitment::calculate(header.storage_commitment, header.class_commitment);

            // There must be at least 1 transaction per block
            let transaction_data = fake_non_empty_with_rng::<
                Vec<_>,
                crate::connection::transaction::dto::TransactionV1,
            >(rng)
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                let mut t: Transaction = t.into();
                let transaction_hash = t.variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
                t.hash = transaction_hash;

                let r: Receipt = crate::connection::transaction::dto::ReceiptV2 {
                    transaction_hash: transaction_hash.as_inner().to_owned().into(),
                    transaction_index: TransactionIndex::new_or_panic(
                        i.try_into().expect("u64 is at least as wide as usize"),
                    ),
                    ..Faker.fake_with_rng(rng)
                }
                .into();
                let e: Vec<Event> = fake_non_empty_with_rng(rng);
                (t, r, e)
            })
            .collect::<Vec<_>>();

            header.transaction_commitment = (config.calculate_transaction_commitment)(
                &transaction_data
                    .iter()
                    .map(|(t, ..)| t.clone())
                    .collect::<Vec<_>>(),
                header.starknet_version,
            )
            .unwrap();

            header.event_commitment = (config.calculate_event_commitment)(
                &transaction_data
                    .iter()
                    .map(|(t, _, e)| (t.hash, e.as_slice()))
                    .collect::<Vec<_>>(),
                header.starknet_version,
            )
            .unwrap();

            header.receipt_commitment = (config.calculate_receipt_commitment)(
                &transaction_data
                    .iter()
                    .map(|(_, r, ..)| r.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();

            header.transaction_count = transaction_data.len();
            header.event_count = transaction_data
                .iter()
                .map(|(_, _, events)| events.len())
                .sum();

            let state_commitment = header.state_commitment;
            let num_cairo_classes = rng.gen_range(0..=0);
            let num_sierra_classes = rng.gen_range(0..=10);

            let cairo_defs = (0..num_cairo_classes)
                .map(|_| {
                    let def = serde_json::to_vec(
                        &Faker.fake_with_rng::<class_definition::Cairo<'_>, _>(rng),
                    )
                    .unwrap();
                    (compute_class_hash(&def).unwrap().hash(), def)
                })
                .collect::<HashMap<_, _>>();
            let sierra_defs = (0..num_sierra_classes)
                .map(|_| {
                    let def = serde_json::to_vec(
                        &Faker.fake_with_rng::<class_definition::Sierra<'_>, _>(rng),
                    )
                    .unwrap();
                    (
                        SierraHash(compute_class_hash(&def).unwrap().hash().0),
                        (def, Faker.fake_with_rng::<String, _>(rng).into_bytes()),
                    )
                })
                .collect::<HashMap<_, _>>();

            let declared_cairo_classes = cairo_defs.keys().copied().collect::<HashSet<_>>();
            let declared_sierra_classes = sierra_defs
                .keys()
                .map(|sierra_hash| (*sierra_hash, Faker.fake()))
                .collect::<HashMap<_, _>>();

            let all_declared_classes_in_this_block = declared_cairo_classes
                .iter()
                .copied()
                .chain(declared_sierra_classes.keys().map(|x| ClassHash(x.0)))
                .collect::<HashSet<_>>();

            init.push(Block {
                header: SignedBlockHeader {
                    header,
                    signature: Faker.fake_with_rng(rng),
                },
                transaction_data,
                state_update: StateUpdate {
                    // Will be fixed after block hash computation
                    block_hash: BlockHash::ZERO,
                    state_commitment,
                    // Will be fixed after block hash computation
                    parent_state_commitment: StateCommitment::ZERO,
                    declared_cairo_classes,
                    declared_sierra_classes,
                    system_contract_updates: HashMap::from([(
                        ContractAddress::ONE,
                        SystemContractUpdate {
                            storage: fake_non_empty_with_rng(rng),
                        },
                    )]),
                    contract_updates: {
                        // We can only deploy what was declared so far in the chain
                        if declared_classes_accum.is_empty() {
                            Default::default()
                        } else {
                            Faker
                                .fake_with_rng::<Vec<ContractAddress>, _>(rng)
                                .into_iter()
                                .map(|contract_address| {
                                    (
                                        contract_address,
                                        ContractUpdate {
                                            class: Some(ContractClassUpdate::Deploy(
                                                *declared_classes_accum.iter().choose(rng).unwrap(),
                                            )),
                                            storage: fake_non_empty_with_rng(rng),
                                            nonce: Faker.fake(),
                                        },
                                    )
                                })
                                .collect()
                        }
                    },
                },
                cairo_defs: cairo_defs.into_iter().collect(),
                sierra_defs: sierra_defs
                    .into_iter()
                    .map(|(h, (s, c))| (h, s, c))
                    .collect(),
            });

            // These new classes from this block can now be deployed in the next blocks
            declared_classes_accum.extend(all_declared_classes_in_this_block);
        }

        // Calculate state commitments and randomly choose which contract updates should
        // be "replace" instead of "deploy"
        if !init.is_empty() {
            let Block {
                header,
                state_update,
                ..
            } = init.get_mut(0).unwrap();
            header.header.state_commitment = StateCommitment::calculate(
                header.header.storage_commitment,
                header.header.class_commitment,
            );
            state_update.parent_state_commitment = StateCommitment::ZERO;

            for i in 1..n {
                let (parent_state_commitment, deployed_in_parent) = init
                    .get(i - 1)
                    .map(
                        |Block {
                             header,
                             state_update,
                             ..
                         }| {
                            (
                                header.header.state_commitment,
                                state_update
                                    .contract_updates
                                    .iter()
                                    .filter_map(|(&address, update)| match update.class {
                                        Some(ContractClassUpdate::Deploy(class_hash)) => {
                                            Some((address, class_hash))
                                        }
                                        Some(_) | None => None,
                                    })
                                    .collect::<Vec<_>>(),
                            )
                        },
                    )
                    .unwrap();
                let Block {
                    header,
                    state_update,
                    ..
                } = init.get_mut(i).unwrap();

                header.header.state_commitment = StateCommitment::calculate(
                    header.header.storage_commitment,
                    header.header.class_commitment,
                );

                //
                // Fix state updates
                //
                state_update.parent_state_commitment = parent_state_commitment;

                let num_deployed_in_parent = deployed_in_parent.len();

                if num_deployed_in_parent > 0 {
                    // Add some replaced classes
                    let num_replaced = rng.gen_range(1..=num_deployed_in_parent);
                    use rand::seq::SliceRandom;

                    deployed_in_parent
                        .choose_multiple(rng, num_replaced)
                        .for_each(|(address, _)| {
                            state_update
                                .contract_updates
                                .entry(*address)
                                // It's unlikely rng has generated an update to the previously
                                // deployed class but it is still possible
                                .or_default()
                                .class =
                                Some(ContractClassUpdate::Replace(Faker.fake_with_rng(rng)));
                        });
                }
            }

            // Compute state diff length and commitment
            // Generate definitions for the implicitly declared classes
            for Block {
                header:
                    SignedBlockHeader {
                        header:
                            BlockHeader {
                                state_diff_length,
                                state_diff_commitment,
                                ..
                            },
                        ..
                    },
                state_update,
                ..
            } in init.iter_mut()
            {
                // CHANGE: no implicitly declared classes
                //
                //
                // All remaining Deploys in the current block should also be
                // added to `declared_cairo_classes` because Cairo0 Deploys
                // were not initially preceded by an explicit declare
                // transaction
                // let implicitly_declared = state_update
                //     .contract_updates
                //     .iter_mut()
                //     .filter_map(|(_, update)| match &mut update.class {
                //         Some(ContractClassUpdate::Deploy(class_hash)) => {
                //             let def = serde_json::to_vec(
                //                 &Faker.fake_with_rng::<class_definition::Cairo<'_>, _>(rng),
                //             )
                //             .unwrap();
                //             let new_hash = compute_class_hash(&def).unwrap().hash();
                //             *class_hash = new_hash;
                //             Some((new_hash, def))
                //         }
                //         Some(ContractClassUpdate::Replace(_)) | None => None,
                //     })
                //     .collect::<Vec<_>>();

                // state_update.declared_cairo_classes.extend(
                //     implicitly_declared
                //         .iter()
                //         .map(|(class_hash, _)| *class_hash),
                // );
                // cairo_defs.extend(implicitly_declared);

                *state_diff_length = state_update.state_diff_length();
                *state_diff_commitment = state_update.compute_state_diff_commitment();
            }

            // Compute the block hash, update parent block hash with the correct
            // value let Block {
            //     header,
            //     state_update,
            //     ..
            // } = init.get_mut(0).unwrap();
            // header.header.parent_hash = BlockHash::ZERO;

            // header.header.hash =
            // (config.calculate_block_hash)(&header.header);

            // state_update.block_hash = header.header.hash;

            // for i in 1..n {
            //     let parent_hash = init
            //         .get(i - 1)
            //         .map(|Block { header, .. }| header.header.hash)
            //         .unwrap();
            //     let Block {
            //         header,
            //         state_update,
            //         ..
            //     } = init.get_mut(i).unwrap();

            //     header.header.parent_hash = parent_hash;

            //     header.header.hash =
            // (config.calculate_block_hash)(&header.header);

            //     state_update.block_hash = header.header.hash;
            // }
        }

        init
    }
}
