//! Basic test fixtures for storage.

use crate::Transaction;
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, CasmHash, ClassHash, ContractAddress, ContractNonce,
    GasPrice, SequencerAddress, SierraHash, StateCommitment, StateUpdate, StorageAddress,
    StorageValue,
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
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockHeader, ClassCommitment, StorageCommitment};

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
            .finalize_with_hash(block_hash!("0xabcd"));

        let mut headers = vec![genesis];
        for i in 1..n {
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
        let mut deployed_contract: Option<(ContractAddress, ClassHash)> = None;

        for (i, header) in headers.iter().enumerate() {
            let i = i as u8;
            let mut state_update = StateUpdate::default()
                .with_block_hash(header.hash)
                .with_state_commitment(header.state_commitment)
                .with_parent_state_commitment(parent_state_commitment)
                .with_storage_update(
                    ContractAddress::new_or_panic(hash!(3, i)),
                    StorageAddress::new_or_panic(hash!(4, i)),
                    StorageValue(hash!(5, i)),
                )
                .with_declared_cairo_class(ClassHash(hash!(6, i)))
                .with_deployed_contract(
                    ContractAddress::new_or_panic(hash!(7, i)),
                    ClassHash(hash!(8, i)),
                )
                .with_contract_nonce(
                    ContractAddress::new_or_panic(hash!(9, i)),
                    ContractNonce(hash!(10, i)),
                )
                .with_declared_sierra_class(SierraHash(hash!(11, i)), CasmHash(hash!(12, i)));

            // Replace the last deployed contract with itself - this doesn't make much sense and should be improved.
            if let Some(deployed) = deployed_contract {
                state_update = state_update.with_replaced_class(deployed.0, deployed.1);
            };

            for declared_class in &state_update.declared_cairo_classes {
                tx.insert_cairo_class(*declared_class, b"").unwrap();
            }

            for (class_hash, compiled_class_hash) in &state_update.declared_sierra_classes {
                tx.insert_sierra_class(class_hash, &[], compiled_class_hash, &[], "1.0.alpha6")
                    .unwrap();
            }

            tx.insert_block_header(header).unwrap();
            tx.insert_state_update(header.number, &state_update)
                .unwrap();

            parent_state_commitment = header.state_commitment;
            deployed_contract = state_update
                .contract_updates
                .iter()
                .filter_map(|(a, u)| u.class.clone().map(|x| (*a, x.class_hash())))
                .last();

            updates.push(state_update);
        }

        updates
    }
}
