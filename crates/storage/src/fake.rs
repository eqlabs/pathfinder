//! Create fake blockchain data for test purposes
use crate::Storage;
use fake::{Fake, Faker};
use pathfinder_common::{BlockHeader, StateUpdate};
use rand::Rng;
use starknet_gateway_types::reply::transaction as gw;

pub type StorageInitializer = Vec<StorageInitializerItem>;

pub type StorageInitializerItem = (
    BlockHeader,
    Vec<(gw::Transaction, gw::Receipt)>,
    StateUpdate,
);

/// Initialize [`Storage`] with fake blocks and state updates
/// maintaining [**limited consistency guarantees**](crate::fake::init::with_n_blocks)
pub fn with_n_blocks(storage: &Storage, n: usize) -> StorageInitializer {
    let mut rng = rand::thread_rng();
    with_n_blocks_and_rng(storage, n, &mut rng)
}

/// Same as [`with_n_blocks`] except caller can specify the rng used
pub fn with_n_blocks_and_rng(
    storage: &Storage,
    n: usize,
    rng: &mut impl Rng,
) -> StorageInitializer {
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();
    let fake_data = init::with_n_blocks_and_rng(n, rng);
    fake_data
        .iter()
        .for_each(|(header, transaction_data, state_update)| {
            tx.insert_block_header(header).unwrap();
            tx.insert_transaction_data(header.hash, header.number, transaction_data)
                .unwrap();

            state_update
                .declared_cairo_classes
                .iter()
                .for_each(|&cairo_class| tx.insert_cairo_class(cairo_class, b"").unwrap());

            state_update
                .declared_sierra_classes
                .iter()
                .for_each(|(sierra_hash, casm_hash)| {
                    tx.insert_sierra_class(sierra_hash, &[], casm_hash, &[], "1.0.alpha6")
                        .unwrap()
                });

            tx.insert_state_update(header.number, &state_update)
                .unwrap();
        });
    tx.commit().unwrap();
    fake_data
}

/// Raw _fake state initializers_
pub mod init {
    use std::collections::{BTreeMap, BTreeSet};

    use super::StorageInitializer;
    use fake::{Fake, Faker};
    use pathfinder_common::test_utils::fake_non_empty_with_rng;
    use pathfinder_common::{
        state_update::ContractClassUpdate, BlockHash, BlockHeader, BlockNumber, ClassHash,
        ContractAddress, StateCommitment, StateUpdate, TransactionIndex,
    };
    use rand::Rng;
    use starknet_gateway_types::reply::transaction as gw;

    /// Create fake blocks and state updates with __limited consistency guarantees__:
    /// - block headers:
    ///     - consecutive numbering starting from genesis (`0`) up to `n-1`
    ///     - parent hash wrt previous block, genesis' parent hash is `0`
    ///     - state commitment is a hash of storage and class commitments
    /// - block bodies:
    ///     - transaction indices within a block
    ///     - transaction hashes in respective receipts
    /// - state updates:
    ///     - block hashes
    ///     - old roots wrt previous state update, genesis' old root is `0`\
    ///     - replaced classes for block N point to some deployed contracts from block N-1
    ///     
    pub fn with_n_blocks(n: usize) -> StorageInitializer {
        let mut rng = rand::thread_rng();
        with_n_blocks_and_rng(n, &mut rng)
    }

    /// Same as [`with_n_blocks`] except caller can specify the rng used
    pub fn with_n_blocks_and_rng(n: usize, rng: &mut impl Rng) -> StorageInitializer {
        let mut init = Vec::with_capacity(n);

        for i in 0..n {
            let mut header: BlockHeader = Faker.fake_with_rng(rng);
            header.number =
                BlockNumber::new_or_panic(i.try_into().expect("u64 is at least as wide as usize"));
            header.state_commitment =
                StateCommitment::calculate(header.storage_commitment, header.class_commitment);

            // There must be at least 1 transaction per block
            let transactions_and_receipts = fake_non_empty_with_rng::<Vec<_>, gw::Transaction>(rng)
                .into_iter()
                .enumerate()
                .map(|(i, t)| {
                    let transaction_hash = t.hash();
                    (
                        t,
                        gw::Receipt {
                            transaction_hash,
                            transaction_index: TransactionIndex::new_or_panic(
                                i.try_into().expect("u64 is at least as wide as usize"),
                            ),
                            ..Faker.fake_with_rng(rng)
                        },
                    )
                })
                .collect::<Vec<_>>();

            let block_hash = header.hash;
            let state_commitment = header.state_commitment;

            init.push((
                header,
                transactions_and_receipts,
                StateUpdate {
                    block_hash,
                    state_commitment,
                    // Will be fixed in the next loop
                    parent_state_commitment: StateCommitment::ZERO,
                    ..Faker.fake_with_rng(rng) // state_diff: StateDiff {
                                               //     storage_diffs: {
                                               //         Faker
                                               //             .fake_with_rng::<BTreeMap<ContractAddress, BTreeSet<StorageEntry>>, _>(
                                               //                 rng,
                                               //             )
                                               //             .into_iter()
                                               //             .map(|(address, entries)| StorageDiff {
                                               //                 address,
                                               //                 storage_entries: entries.into_iter().collect(),
                                               //             })
                                               //             .collect()
                                               //     },
                                               //     // Will be fixed in the next loop
                                               //     replaced_classes: vec![],
                                               //     ..Faker.fake_with_rng(rng)
                                               // },
                },
            ));
        }

        //
        // "Fix" block headers and state updates
        //
        if !init.is_empty() {
            let (header, _, state_update) = init.get_mut(0).unwrap();
            header.parent_hash = BlockHash::ZERO;
            header.state_commitment =
                StateCommitment::calculate(header.storage_commitment, header.class_commitment);
            state_update.block_hash = header.hash;
            state_update.parent_state_commitment = StateCommitment::ZERO;

            // Disallow empty storage entries
            state_update.contract_updates.iter_mut().for_each(|(_, x)| {
                if x.storage.is_empty() {
                    x.storage
                        .insert(Faker.fake_with_rng(rng), Faker.fake_with_rng(rng));
                }
            });

            state_update
                .system_contract_updates
                .iter_mut()
                .for_each(|(_, x)| {
                    if x.storage.is_empty() {
                        x.storage
                            .insert(Faker.fake_with_rng(rng), Faker.fake_with_rng(rng));
                    }
                });

            for i in 1..n {
                let (parent_hash, parent_state_commitment, deployed_in_parent) = init
                    .get(i - 1)
                    .map(|(h, _, state_update)| {
                        (
                            h.hash,
                            h.state_commitment,
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
                    })
                    .unwrap();
                let (header, _, state_update) = init.get_mut(i).unwrap();

                header.parent_hash = parent_hash;
                header.state_commitment =
                    StateCommitment::calculate(header.storage_commitment, header.class_commitment);
                state_update.block_hash = header.hash;

                //
                // Fix state updates
                //
                state_update.parent_state_commitment = parent_state_commitment;

                // Disallow empty storage entries
                state_update.contract_updates.iter_mut().for_each(|(_, u)| {
                    if u.storage.is_empty() {
                        u.storage
                            .insert(Faker.fake_with_rng(rng), Faker.fake_with_rng(rng));
                    }
                });

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
        }

        init
    }
}
