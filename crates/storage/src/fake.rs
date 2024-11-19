//! Create fake blockchain storage for test purposes
use std::collections::{HashMap, HashSet};

use fake::{Fake, Faker};
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::state_update::{
    ContractClassUpdate,
    ContractUpdate,
    StateUpdateRef,
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
    ClassCommitment,
    ClassHash,
    ContractAddress,
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
    TransactionIndex,
};
use rand::seq::IteratorRandom;
use rand::Rng;
use starknet_gateway_types::class_hash::compute_class_hash;

use crate::{Storage, StorageBuilder};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Block {
    pub header: SignedBlockHeader,
    pub transaction_data: Vec<(Transaction, Receipt, Vec<Event>)>,
    pub state_update: Option<StateUpdate>,
    pub cairo_defs: Vec<(ClassHash, Vec<u8>)>, // Cairo 0 definitions
    pub sierra_defs: Vec<(SierraHash, Vec<u8>, Vec<u8>)>, // Sierra + Casm definitions
}

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            calculate_block_hash: Box::new(|_| Faker.fake()),
            calculate_transaction_commitment: Box::new(|_, _| Ok(Faker.fake())),
            calculate_receipt_commitment: Box::new(|_| Ok(Faker.fake())),
            calculate_event_commitment: Box::new(|_, _| Ok(Faker.fake())),
            update_tries: Box::new(|_, _, _, _, _| Ok((Faker.fake(), Faker.fake()))),
        }
    }
}

pub fn fill(storage: &Storage, blocks: &[Block], update_tries: Option<UpdateTriesFn>) {
    let mut db = storage.connection().unwrap();
    let db = db.transaction().unwrap();

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

            if let Some(state_update) = state_update {
                db.insert_state_update(header.header.number, state_update)
                    .unwrap();

                if let Some(update_tries) = &update_tries {
                    update_tries(
                        &db,
                        state_update.into(),
                        false,
                        header.header.number,
                        storage.clone(),
                    )
                    .unwrap();
                }
            }

            cairo_defs.iter().for_each(|(cairo_hash, definition)| {
                db.update_cairo_class(*cairo_hash, definition).unwrap()
            });

            sierra_defs
                .iter()
                .for_each(|(sierra_hash, sierra_definition, casm_definition)| {
                    db.update_sierra_class(
                        sierra_hash,
                        sierra_definition,
                        state_update
                            .as_ref()
                            .unwrap()
                            .declared_sierra_classes
                            .get(sierra_hash)
                            .unwrap(),
                        casm_definition,
                    )
                    .unwrap()
                });
        },
    );

    db.commit().unwrap();
}

/// Create fake blocks and state updates with __limited consistency
/// guarantees__:
/// - starknet version: 0.13.2
/// - chain id: `SEPOLIA_TESTNET`
/// - block headers:
///     - consecutive numbering starting from genesis (`0`) up to `n-1`
///     - parent hash of block N points to hash of block N-1, parent hash of
///       genesis is 0
///     - state commitment is a hash of storage and class commitments
///     - state diff length and commitment are correctly calculated from its
///       respective state update
/// - block bodies:
///     - transaction indices within a block
///     - transaction hashes in respective receipts
///     - at least 1 transaction with receipt per block
/// - state updates:
///     - block hashes
///     - parent state commitment of block N points to state commitment of block
///       N-1, parent state commitment of genesis is 0
///     - no replaced classes
///     - each storage diff has its respective nonce update
///     - storage entries constrain at least 1 element
///     - no implicitly declared classes (ie. as in the old deploy transactions
///       that were not preceded by a declare transaction)
/// - declared cairo|sierra definitions
///     - class definition is a serialized to JSON representation of
///       `class_definition::Cairo|Sierra` respectively with random fields
///     - all those definitions are very short and fall far below the soft limit
///       in protobuf encoding
///     - casm definitions for sierra classes are purely random Strings
///     - cairo class hashes and sierra class hashes are correctly calculated
///       from the definitions, casm hashes are random
/// - transactions
///     - transaction hashes are calculated from their respective variant, with
///       ChainId set to `SEPOLIA_TESTNET`
pub mod generate {
    use super::*;

    pub fn n_blocks(n: usize) -> Vec<Block> {
        with_config(n, Default::default())
    }

    pub fn with_config(n: usize, config: Config) -> Vec<Block> {
        with_rng_and_config(n, &mut rand::thread_rng(), config)
    }

    pub fn with_rng_and_config<R: Rng>(n: usize, rng: &mut R, config: Config) -> Vec<Block> {
        let Config {
            calculate_block_hash,
            calculate_transaction_commitment,
            calculate_receipt_commitment,
            calculate_event_commitment,
            update_tries,
        } = config;

        let mut blocks = generate_inner(
            n,
            rng,
            calculate_transaction_commitment,
            calculate_receipt_commitment,
            calculate_event_commitment,
        );

        update_commitments(&mut blocks, update_tries);
        compute_block_hashes(&mut blocks, calculate_block_hash);
        blocks
    }

    fn generate_inner<R: Rng>(
        n: usize,
        rng: &mut R,
        calculate_transaction_commitment: TransactionCommitmentFn,
        calculate_receipt_commitment: ReceiptCommitmentFn,
        calculate_event_commitment: EventCommitmentFn,
    ) -> Vec<Block> {
        let mut init = Vec::with_capacity(n);
        let mut declared_classes_accum = HashSet::new();

        for i in 0..n {
            let mut header: BlockHeader = Faker.fake_with_rng(rng);
            header.starknet_version = StarknetVersion::V_0_13_2;
            header.number =
                BlockNumber::new_or_panic(i.try_into().expect("u64 is at least as wide as usize"));
            // Will be fixed after inserting tries
            header.state_commitment = StateCommitment::ZERO;

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

            header.transaction_commitment = (calculate_transaction_commitment)(
                &transaction_data
                    .iter()
                    .map(|(t, ..)| t.clone())
                    .collect::<Vec<_>>(),
                header.starknet_version,
            )
            .unwrap();

            header.event_commitment = (calculate_event_commitment)(
                &transaction_data
                    .iter()
                    .map(|(t, _, e)| (t.hash, e.as_slice()))
                    .collect::<Vec<_>>(),
                header.starknet_version,
            )
            .unwrap();

            header.receipt_commitment = (calculate_receipt_commitment)(
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
                state_update: Some(StateUpdate {
                    // Will be fixed after block hash computation
                    block_hash: BlockHash::ZERO,
                    // Will be fixed after inserting tries
                    state_commitment: StateCommitment::ZERO,
                    // Will be fixed after inserting tries
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
                }),
                cairo_defs: cairo_defs.into_iter().collect(),
                sierra_defs: sierra_defs
                    .into_iter()
                    .map(|(h, (s, c))| (h, s, c))
                    .collect(),
            });

            // These new classes from this block can now be deployed in the next blocks
            declared_classes_accum.extend(all_declared_classes_in_this_block);
        }

        // FIXME Previous way of faking replaced classes made trie generation using
        // `update_starknet_state` unstable, ie. state roots did not match
        // between the generated block data and what was computed as a result of
        // checkpoint or tracking sync test.

        // Compute state diff length and commitment
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
            *state_diff_length = state_update.as_ref().unwrap().state_diff_length();
            *state_diff_commitment = state_update
                .as_ref()
                .unwrap()
                .compute_state_diff_commitment();
        }

        init
    }

    // Updates class, storage and state commitments
    fn update_commitments(blocks: &mut [Block], update_tries: UpdateTriesFn) {
        // This dummy db is only necessary to build the tries whose roots are the
        // storage and class commitments
        let dummy_storage = StorageBuilder::in_tempdir().unwrap();
        let mut db = dummy_storage.connection().unwrap();
        let db = db.transaction().unwrap();

        for Block {
            header,
            state_update,
            ..
        } in blocks.iter_mut()
        {
            let state_update = state_update.as_mut().unwrap();

            // Required because of foreign key constraint
            db.insert_block_header(&header.header).unwrap();
            // Required for the tries
            db.insert_state_update(header.header.number, state_update)
                .unwrap();
            let (storage_commitment, class_commitment) = update_tries(
                &db,
                state_update.into(),
                false,
                header.header.number,
                dummy_storage.clone(),
            )
            .unwrap();
            let state_commitment = StateCommitment::calculate(storage_commitment, class_commitment);
            header.header.storage_commitment = storage_commitment;
            header.header.class_commitment = class_commitment;
            header.header.state_commitment = state_commitment;
            state_update.state_commitment = state_commitment;
        }

        for i in 1..blocks.len() {
            let parent_state_commitment = blocks.get(i - 1).unwrap().header.header.state_commitment;
            let Block { state_update, .. } = blocks.get_mut(i).unwrap();
            let state_update = state_update.as_mut().unwrap();
            state_update.parent_state_commitment = parent_state_commitment;
        }
    }

    // Computes block hashes, updates parent block hashes with the correct values
    fn compute_block_hashes(blocks: &mut [Block], calculate_block_hash: BlockHashFn) {
        if blocks.is_empty() {
            return;
        }

        let Block {
            header,
            state_update,
            ..
        } = blocks.get_mut(0).unwrap();
        header.header.parent_hash = BlockHash::ZERO;
        header.header.hash = calculate_block_hash(&header.header);
        state_update.as_mut().unwrap().block_hash = header.header.hash;

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
            state_update.as_mut().unwrap().block_hash = header.header.hash;
        }
    }
}
