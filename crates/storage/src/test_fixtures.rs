//! Basic test fixtures for storage.

use crate::Transaction;
use crate::{
    types::{
        state_update::{DeclaredSierraClass, DeployedContract, StateDiff},
        StateUpdate,
    },
    Storage,
};
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, CasmHash, ClassHash, ContractAddress, ContractNonce,
    GasPrice, SequencerAddress, SierraHash, StateCommitment, StorageAddress, StorageValue,
};
use stark_hash::Felt;

/// Generate [`Felt`] from a sequence of bytes.
macro_rules! hash {
    ($($value:expr),*) => {
        Felt::from_be_slice(&[$($value),*]).unwrap()
    };
}

pub(crate) use hash;

/// Initializers for storage test fixtures.
pub mod init {
    use super::*;
    use pathfinder_common::{felt, BlockHeader, ClassCommitment, StorageCommitment};

    /// Inserts `n` state updates, referring to blocks with numbers `(0..n)` and hashes `("0x0".."0xn")` respectively.
    pub fn with_n_state_updates(tx: &Transaction<'_>, n: u8) -> Vec<StateUpdate> {
        if n == 0 {
            return vec![];
        }

        let genesis = BlockHeader::builder()
            .with_number(BlockNumber::GENESIS)
            .with_storage_commitment(StorageCommitment(hash!(11, 0)))
            .with_class_commitment(ClassCommitment(hash!(12, 0)))
            .with_calculated_state_commitment()
            .with_timestamp(BlockTimestamp::new_or_panic(1000))
            .with_gas_price(GasPrice(2000))
            .with_sequencer_address(SequencerAddress(hash!(2, 0)))
            .with_calculated_state_commitment()
            .finalize_with_hash(BlockHash(felt!("0xabcd")));

        let mut headers = vec![genesis];
        for i in 1..n {
            let i = i as u8;
            let header = headers
                .last()
                .unwrap()
                .child_builder()
                .with_storage_commitment(StorageCommitment(hash!(11, i)))
                .with_class_commitment(ClassCommitment(hash!(12, i)))
                .with_calculated_state_commitment()
                .with_timestamp(BlockTimestamp::new_or_panic(i as u64 + 1000))
                .with_gas_price(GasPrice(i as u128 + 2000))
                .with_sequencer_address(SequencerAddress(hash!(2, i)))
                .finalize_with_hash(BlockHash(hash!(i)));
            headers.push(header);
        }

        let mut updates = Vec::new();

        let mut parent_state_commitment = StateCommitment::ZERO;
        let mut deployed_contract: Option<DeployedContract> = None;

        for (i, header) in headers.iter().enumerate() {
            let i = i as u8;
            let mut state_diff = StateDiff::default()
                .add_storage_update(
                    ContractAddress::new_or_panic(hash!(3, i)),
                    StorageAddress::new_or_panic(hash!(4, i)),
                    StorageValue(hash!(5, i)),
                )
                .add_declared_cairo_class(ClassHash(hash!(6, i)))
                .add_deployed_contract(
                    ContractAddress::new_or_panic(hash!(7, i)),
                    ClassHash(hash!(8, i)),
                )
                .add_nonce_update(
                    ContractAddress::new_or_panic(hash!(9, i)),
                    ContractNonce(hash!(10, i)),
                )
                .add_declared_sierra_class(SierraHash(hash!(11, i)), CasmHash(hash!(12, i)));

            // Replace the last deployed contract.
            if let Some(deployed) = deployed_contract {
                state_diff = state_diff.add_replaced_class(deployed.address, deployed.class_hash);
            };

            let update = StateUpdate {
                block_hash: Some(header.hash),
                new_root: header.state_commitment,
                old_root: parent_state_commitment,
                state_diff,
            };

            for declared_class in &update.state_diff.declared_contracts {
                tx.insert_cairo_class(declared_class.class_hash, b"")
                    .unwrap();
            }

            for DeclaredSierraClass {
                class_hash,
                compiled_class_hash,
            } in &update.state_diff.declared_sierra_classes
            {
                tx.insert_sierra_class(class_hash, &[], compiled_class_hash, &[], "1.0.alpha6")
                    .unwrap();
            }

            tx.insert_block_header(header).unwrap();
            tx.insert_state_diff(header.number, &update.state_diff)
                .unwrap();

            parent_state_commitment = header.state_commitment;
            deployed_contract = update.state_diff.deployed_contracts.last().cloned();

            updates.push(update);
        }

        updates
    }
}

/// Creates test storage in memory that contains N state updates,
/// referring to blocks with numbers (0..N) and ("0x0".."0xN") hashes respectively.
pub fn with_n_state_updates<F>(n: u8, f: F)
where
    F: FnOnce(&Storage, &Transaction<'_>, Vec<StateUpdate>),
{
    let storage = Storage::in_memory().unwrap();
    let mut connection = storage.connection().unwrap();
    let tx = connection.transaction().unwrap();

    f(&storage, &tx, init::with_n_state_updates(&tx, n))
}
