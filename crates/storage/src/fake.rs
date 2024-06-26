//! Create fake blockchain data for test purposes
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::transaction::Transaction;
use pathfinder_common::{ClassHash, SierraHash, SignedBlockHeader, StateUpdate};
use rand::Rng;

use crate::Storage;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Block {
    pub header: SignedBlockHeader,
    pub transaction_data: Vec<(Transaction, Receipt, Vec<Event>)>,
    pub state_update: StateUpdate,
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
         }| {
            tx.insert_block_header(&header.header).unwrap();
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
            tx.insert_signature(header.header.number, &header.signature)
                .unwrap();
            tx.update_state_diff_commitment_and_length(
                header.header.number,
                header.state_diff_commitment,
                header.state_diff_length,
            )
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

            tx.insert_state_update(header.header.number, state_update)
                .unwrap();
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

/// Raw _fake state initializers_
pub mod init {
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
        ContractAddress,
        SignedBlockHeader,
        StateCommitment,
        StateUpdate,
        TransactionIndex,
    };
    use rand::Rng;

    use super::Block;

    /// Create fake blocks and state updates with __limited consistency
    /// guarantees__:
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, parent hash of the genesis block
    ///       is `0s`
    ///     - state commitment is a hash of storage and class commitments
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    ///     - at least 1 transaction with receipt per block
    /// - state updates:
    ///     - block hashes
    ///     - old roots wrt previous state update, old root of the genesis state
    ///       update is `0s`
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
    /// - transactions
    ///     - transaction hashes are calculated from their respective variant,
    ///       with ChainId set to `SEPOLIA_TESTNET`
    pub fn with_n_blocks(n: usize) -> Vec<Block> {
        let mut rng = rand::thread_rng();
        with_n_blocks_and_rng(n, &mut rng)
    }

    /// Same as [`with_n_blocks`] except caller can specify the rng used
    pub fn with_n_blocks_and_rng<R: Rng>(n: usize, rng: &mut R) -> Vec<Block> {
        let mut init = Vec::with_capacity(n);

        for i in 0..n {
            let mut header: BlockHeader = Faker.fake_with_rng(rng);
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

                let r: Receipt = crate::connection::transaction::dto::ReceiptV1 {
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

            header.transaction_count = transaction_data.len();
            header.event_count = transaction_data
                .iter()
                .map(|(_, _, events)| events.len())
                .sum();

            let block_hash = header.hash;
            let state_commitment = header.state_commitment;
            let declared_cairo_classes = Faker.fake_with_rng::<HashSet<_>, _>(rng);
            let declared_sierra_classes = Faker.fake_with_rng::<HashMap<_, _>, _>(rng);

            let cairo_defs = declared_cairo_classes
                .iter()
                .map(|&class_hash| {
                    (
                        class_hash,
                        serde_json::to_vec(
                            &Faker.fake_with_rng::<class_definition::Cairo<'_>, _>(rng),
                        )
                        .unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let sierra_defs = declared_sierra_classes
                .iter()
                .map(|(&sierra_hash, _)| {
                    (
                        sierra_hash,
                        serde_json::to_vec(
                            &Faker.fake_with_rng::<class_definition::Sierra<'_>, _>(rng),
                        )
                        .unwrap(),
                        Faker.fake_with_rng::<String, _>(rng).into_bytes(),
                    )
                })
                .collect::<Vec<_>>();

            init.push(Block {
                header: SignedBlockHeader {
                    header,
                    signature: Faker.fake_with_rng(rng),
                    ..Default::default()
                },
                transaction_data,
                state_update: StateUpdate {
                    block_hash,
                    state_commitment,
                    // Will be fixed in the next loop
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
                        let mut x = Faker.fake_with_rng::<HashMap<_, ContractUpdate>, _>(rng);
                        x.iter_mut().for_each(|(_, u)| {
                            // Initially generate deploys only
                            u.class = u
                                .class
                                .as_ref()
                                .map(|x| ContractClassUpdate::Deploy(x.class_hash()));
                            // Disallow empty storage entries
                            if u.storage.is_empty() {
                                u.storage = fake_non_empty_with_rng(rng);
                            }
                        });
                        x
                    },
                },
                cairo_defs,
                sierra_defs,
            });
        }

        //
        // "Fix" block headers and state updates
        //
        if !init.is_empty() {
            let Block {
                header,
                state_update,
                ..
            } = init.get_mut(0).unwrap();
            header.header.parent_hash = BlockHash::ZERO;
            header.header.state_commitment = StateCommitment::calculate(
                header.header.storage_commitment,
                header.header.class_commitment,
            );
            state_update.block_hash = header.header.hash;
            state_update.parent_state_commitment = StateCommitment::ZERO;

            for i in 1..n {
                let (parent_hash, parent_state_commitment, deployed_in_parent) = init
                    .get(i - 1)
                    .map(
                        |Block {
                             header,
                             state_update,
                             ..
                         }| {
                            (
                                header.header.hash,
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

                header.header.parent_hash = parent_hash;
                header.header.state_commitment = StateCommitment::calculate(
                    header.header.storage_commitment,
                    header.header.class_commitment,
                );
                state_update.block_hash = header.header.hash;

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
                                // It's ulikely rng has generated an update to the previously
                                // deployed class but it is still possible
                                .or_default()
                                .class =
                                Some(ContractClassUpdate::Replace(Faker.fake_with_rng(rng)));
                        });
                }
            }

            // Update counts
            for Block {
                header:
                    SignedBlockHeader {
                        state_diff_length,
                        state_diff_commitment,
                        header:
                            BlockHeader {
                                starknet_version, ..
                            },
                        ..
                    },
                state_update,
                cairo_defs,
                ..
            } in init.iter_mut()
            {
                // All remaining Deploys in the current block should also be
                // added to `declared_cairo_classes` because Cairo0 Deploys
                // were not initially preceded by an explicit declare
                // transaction
                let implicitly_declared =
                    state_update
                        .contract_updates
                        .iter()
                        .filter_map(|(_, update)| match update.class {
                            Some(ContractClassUpdate::Deploy(class_hash)) => Some(class_hash),
                            Some(ContractClassUpdate::Replace(_)) | None => None,
                        });

                state_update
                    .declared_cairo_classes
                    .extend(implicitly_declared.clone());
                cairo_defs.extend(implicitly_declared.map(|class_hash| {
                    (
                        class_hash,
                        serde_json::to_vec(
                            &Faker.fake_with_rng::<class_definition::Cairo<'_>, _>(rng),
                        )
                        .unwrap(),
                    )
                }));

                *state_diff_length += u64::try_from(
                    state_update.contract_updates.iter().fold(
                        state_update
                            .system_contract_updates
                            .iter()
                            .fold(0, |acc, (_, u)| acc + u.storage.len()),
                        |acc, (_, u)| acc + u.storage.len(),
                    ),
                )
                .expect("ptr size is 64 bits");
                *state_diff_length += u64::try_from(
                    state_update
                        .contract_updates
                        .iter()
                        .filter(|(_, u)| u.nonce.is_some())
                        .count(),
                )
                .expect("ptr size is 64 bits");
                *state_diff_length = u64::try_from(
                    state_update.declared_cairo_classes.len()
                        + state_update.declared_sierra_classes.len(),
                )
                .expect("ptr size is 64 bits");
                *state_diff_length = u64::try_from(
                    state_update
                        .contract_updates
                        .iter()
                        .filter(|(_, u)| u.class.is_some())
                        .count(),
                )
                .expect("ptr size is 64 bits");

                *state_diff_commitment =
                    state_update.compute_state_diff_commitment(*starknet_version);
            }
        }

        init
    }
}
