//! Create fake blockchain data for test purposes
use crate::Storage;
use pathfinder_common::event::Event;
use pathfinder_common::receipt::Receipt;
use pathfinder_common::{transaction as common, SignedBlockHeader};
use pathfinder_common::{ClassHash, SierraHash, StateUpdate};
use rand::Rng;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Block {
    pub header: SignedBlockHeader,
    pub transaction_data: Vec<(common::Transaction, Receipt, Vec<Event>)>,
    pub state_update: StateUpdate,
    pub cairo_defs: Vec<(ClassHash, Vec<u8>)>, // Cairo 0 definitions
    pub sierra_defs: Vec<(SierraHash, Vec<u8>, Vec<u8>)>, // Sierra + Casm definitions
}

/// Initialize [`Storage`] with fake blocks and state updates
/// maintaining [**limited consistency guarantees**](crate::fake::init::with_n_blocks)
pub fn with_n_blocks(storage: &Storage, n: usize) -> Vec<Block> {
    let mut rng = rand::thread_rng();
    with_n_blocks_and_rng(storage, n, &mut rng)
}

/// Same as [`with_n_blocks`] except caller can specify the rng used
pub fn with_n_blocks_and_rng<R: Rng>(storage: &Storage, n: usize, rng: &mut R) -> Vec<Block> {
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();
    let fake_data = init::with_n_blocks_and_rng(n, rng);
    fake_data.iter().for_each(
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
                    .map(|(tx, receipt, events)| crate::TransactionData {
                        transaction: tx,
                        receipt: Some(receipt),
                        events: Some(events),
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            tx.insert_signature(header.header.number, &header.signature)
                .unwrap();
            tx.insert_state_update_counts(header.header.number, &header.state_update_counts)
                .unwrap();

            state_update
                .declared_cairo_classes
                .iter()
                .zip(cairo_defs.iter())
                .for_each(|(&cairo_hash, (_, definition))| {
                    tx.insert_cairo_class(cairo_hash, definition).unwrap()
                });

            state_update
                .declared_sierra_classes
                .iter()
                .zip(sierra_defs.iter())
                .for_each(
                    |((sierra_hash, casm_hash), (_, sierra_definition, casm_definition))| {
                        tx.insert_sierra_class(
                            sierra_hash,
                            sierra_definition,
                            casm_hash,
                            casm_definition,
                        )
                        .unwrap()
                    },
                );

            tx.insert_state_update(header.header.number, state_update)
                .unwrap();
        },
    );
    tx.commit().unwrap();
    fake_data
}

/// Raw _fake state initializers_
pub mod init {
    use std::collections::{HashMap, HashSet};

    use fake::{Fake, Faker};
    use pathfinder_common::event::Event;
    use pathfinder_common::receipt::Receipt;
    use pathfinder_common::state_update::{ContractUpdate, SystemContractUpdate};
    use pathfinder_common::test_utils::fake_non_empty_with_rng;
    use pathfinder_common::ContractAddress;
    use pathfinder_common::{
        state_update::ContractClassUpdate, BlockHash, BlockHeader, BlockNumber, StateCommitment,
        StateUpdate, TransactionIndex,
    };
    use pathfinder_common::{transaction as common, SignedBlockHeader};
    use rand::Rng;
    use starknet_gateway_types::class_definition;

    use super::Block;

    /// Create fake blocks and state updates with __limited consistency guarantees__:
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, genesis' parent hash is `0`
    ///     - state commitment is a hash of storage and class commitments
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    ///     - at least 1 transaction with receipt per block
    /// - state updates:
    ///     - block hashes
    ///     - old roots wrt previous state update, genesis' old root is `0`
    ///     - replaced classes for block N point to some deployed contracts from block N-1
    ///     - each storage diff has its respective nonce update
    ///     - storage entries constrain at least 1 element
    /// - declared cairo|sierra definitions
    ///     - each declared class has random bytes inserted as its definition
    ///     - all those definitions are **very short and fall far below the soft limit in protobuf
    ///       encoding of 1MiB**, btw see usage of `p2p_proto::MESSAGE_SIZE_LIMIT` et al.
    ///     - casm definitions for sierra classes are empty
    ///
    ///     
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
                crate::connection::transaction::dto::Transaction,
            >(rng)
            .into_iter()
            .enumerate()
            .map(|(i, t)| {
                let t: common::Transaction = t.into();
                let transaction_hash = t.hash;

                let r: Receipt = crate::connection::transaction::dto::Receipt::V0(
                    crate::connection::transaction::dto::ReceiptV0 {
                        transaction_hash: transaction_hash.as_inner().to_owned().into(),
                        transaction_index: TransactionIndex::new_or_panic(
                            i.try_into().expect("u64 is at least as wide as usize"),
                        ),
                        ..Faker.fake_with_rng(rng)
                    },
                )
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
                                // It's ulikely rng has generated an update to the previously deployed class but it is still possible
                                .or_default()
                                .class =
                                Some(ContractClassUpdate::Replace(Faker.fake_with_rng(rng)))
                        })
                }
            }

            // Update counts
            for Block {
                header:
                    SignedBlockHeader {
                        state_update_counts,
                        ..
                    },
                state_update,
                ..
            } in init.iter_mut()
            {
                state_update_counts.storage_diffs = state_update.contract_updates.iter().fold(
                    state_update
                        .system_contract_updates
                        .iter()
                        .fold(0, |acc, (_, u)| acc + u.storage.len()),
                    |acc, (_, u)| acc + u.storage.len(),
                ) as u64;
                state_update_counts.nonce_updates = state_update
                    .contract_updates
                    .iter()
                    .filter(|(_, u)| u.nonce.is_some())
                    .count() as u64;
                state_update_counts.declared_classes = (state_update.declared_cairo_classes.len()
                    + state_update.declared_sierra_classes.len())
                    as u64;
                state_update_counts.deployed_contracts = state_update
                    .contract_updates
                    .iter()
                    .filter(|(_, u)| u.class.is_some())
                    .count() as u64;
            }
        }

        init
    }
}
