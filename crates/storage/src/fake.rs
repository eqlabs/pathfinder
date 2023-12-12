//! Create fake blockchain data for test purposes
use crate::Storage;
use pathfinder_common::{
    signature::BlockCommitmentSignature, BlockHeader, ClassHash, SierraHash, StateUpdate,
};
use rand::Rng;
use starknet_gateway_types::reply::transaction as gw;

pub type StorageInitializer = Vec<StorageInitializerItem>;

pub type StorageInitializerItem = (
    BlockHeader,
    BlockCommitmentSignature,
    Vec<(gw::Transaction, gw::Receipt)>,
    StateUpdate,
    Vec<(ClassHash, Vec<u8>)>,  // Cairo 0 definitions
    Vec<(SierraHash, Vec<u8>)>, // Sierra definitions
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
    fake_data.iter().for_each(
        |(header, signature, transaction_data, state_update, cairo_defs, sierra_defs)| {
            tx.insert_block_header(header).unwrap();
            tx.insert_transaction_data(header.hash, header.number, transaction_data)
                .unwrap();
            tx.insert_signature(header.number, signature).unwrap();

            // Insert class definitions.
            for (hash, definition) in cairo_defs {
                tx.insert_cairo_class(*hash, definition).unwrap()
            }

            for (sierra_hash, definition) in sierra_defs {
                let casm_hash = state_update
                    .declared_sierra_classes
                    .get(sierra_hash)
                    .unwrap();
                tx.insert_sierra_class(sierra_hash, definition, casm_hash, &[], "1.0.alpha6")
                    .unwrap()
            }

            tx.insert_state_update(header.number, state_update).unwrap();
        },
    );
    tx.commit().unwrap();
    fake_data
}

/// Raw _fake state initializers_
pub mod init {
    use std::collections::{HashMap, HashSet};

    use crate::fake::StorageInitializerItem;

    use super::StorageInitializer;
    use fake::{Fake, Faker};
    use pathfinder_common::state_update::SystemContractUpdate;
    use pathfinder_common::test_utils::fake_non_empty_with_rng;
    use pathfinder_common::{BlockHeader, StateCommitment, StateUpdate, TransactionIndex};
    use pathfinder_common::{
        ClassHash, ContractAddress, ContractNonce, SierraHash, StorageAddress, StorageValue,
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
    pub fn with_n_blocks(n: usize) -> StorageInitializer {
        let mut rng = rand::thread_rng();
        with_n_blocks_and_rng(n, &mut rng)
    }

    /// Same as [`with_n_blocks`] except caller can specify the rng used
    pub fn with_n_blocks_and_rng(n: usize, rng: &mut impl Rng) -> StorageInitializer {
        use rand::seq::IteratorRandom;

        let mut data: Vec<StorageInitializerItem> = Vec::with_capacity(n);

        let mut declared = HashSet::new();
        let mut deployed = HashSet::new();

        for _ in 0..n {
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

            let mut header: BlockHeader = Faker.fake_with_rng(rng);
            let parent = data.last().map(|d| &d.0);
            header.number = parent
                .map(|d| d.number.clone().next().unwrap())
                .unwrap_or_default();
            header.parent_hash = parent.map(|d| d.hash).unwrap_or_default();
            header.state_commitment =
                StateCommitment::calculate(header.storage_commitment, header.class_commitment);
            header.transaction_count = transactions_and_receipts.len();
            header.event_count = transactions_and_receipts
                .iter()
                .map(|(_, r)| r.events.len())
                .sum();

            let mut declared_cairo_classes = fake_non_empty_with_rng::<HashSet<_>, _>(rng);
            declared_cairo_classes.retain(|x| !declared.contains(x));

            let mut declared_sierra_classes =
                fake_non_empty_with_rng::<HashMap<SierraHash, _>, _>(rng);
            declared_sierra_classes.retain(|x, _| !declared.contains(&ClassHash(x.0)));

            let cairo_definitions = declared_cairo_classes
                .iter()
                .map(|&class_hash| (class_hash, Faker.fake_with_rng::<Vec<u8>, _>(rng)))
                .collect::<Vec<_>>();
            let sierra_definitions = declared_sierra_classes
                .iter()
                .map(|(&sierra_hash, _)| (sierra_hash, Faker.fake_with_rng::<Vec<u8>, _>(rng)))
                .collect::<Vec<_>>();

            let mut state_update = StateUpdate::default()
                .with_block_hash(header.hash)
                .with_state_commitment(header.state_commitment)
                .with_parent_state_commitment(
                    parent.map(|d| d.state_commitment).unwrap_or_default(),
                );

            // Declare the classes
            for cairo in declared_cairo_classes {
                state_update = state_update.with_declared_cairo_class(cairo);
                declared.insert(cairo);
            }
            for (sierra, casm) in declared_sierra_classes {
                state_update = state_update.with_declared_sierra_class(sierra, casm);
                declared.insert(ClassHash(sierra.0));
            }

            // Replace some contracts classes. This must occur before deploying new contracts
            // in this block. A contract cannot be both deployed and replaced within the same
            // block.
            if !deployed.is_empty() {
                let replaced = deployed.iter().choose_multiple(rng, 3);

                for contract in replaced {
                    let class = declared.iter().choose(rng).unwrap();
                    state_update = state_update.with_replaced_class(*contract, *class)
                }
            }

            // Deploy some new contracts.
            let contracts: HashSet<ContractAddress> = fake_non_empty_with_rng(rng);
            for contract in contracts {
                let class = declared.iter().choose(rng).unwrap();
                state_update = state_update.with_deployed_contract(contract, *class);
                deployed.insert(contract);
            }

            // Update some contract nonces. Technically these should be present
            // for every contract update, but randomly should be okay as well.
            let nonces: Vec<ContractNonce> = fake_non_empty_with_rng(rng);
            for nonce in nonces {
                let contract = deployed.iter().choose(rng).unwrap();
                state_update = state_update.with_contract_nonce(*contract, nonce);
            }

            // Update some storage.
            let updates: HashMap<StorageAddress, StorageValue> = Faker.fake_with_rng(rng);
            for (key, value) in updates {
                let contract = deployed.iter().choose(rng).unwrap();
                state_update = state_update.with_storage_update(*contract, key, value);
            }

            // Generate some system contract updates.
            let system_updates = SystemContractUpdate {
                storage: fake_non_empty_with_rng(rng),
            };
            for (key, value) in system_updates.storage {
                state_update =
                    state_update.with_system_storage_update(ContractAddress::ONE, key, value);
            }

            data.push((
                header,
                Faker.fake_with_rng(rng),
                transactions_and_receipts,
                state_update,
                cairo_definitions,
                sierra_definitions,
            ));
        }

        data
    }
}
