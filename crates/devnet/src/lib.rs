//! Utilities for initializing a devnet for development and testing purposes.
//! Heavily inspired by [starknet-devnet](https://github.com/0xSpaceShard/starknet-devnet) v0.7.1.
//! Unfortunately we cannot use `starknet-devnet` directly because it is not
//! state/storage API agnostic.

use pathfinder_crypto::Felt;
use starknet_api::hash::StarkHash;

mod account;
mod class;
mod contract;
mod fixtures;
mod utils;

pub trait IntoFelt {
    fn into_felt(self) -> Felt;
}

impl IntoFelt for StarkHash {
    fn into_felt(self) -> Felt {
        Felt::from_be_bytes(self.to_bytes_be()).expect("not to overflow")
    }
}

pub trait IntoTypesCoreFelt {
    fn into_types_core_felt(self) -> starknet_types_core::felt::Felt;
}

impl IntoTypesCoreFelt for Felt {
    fn into_types_core_felt(self) -> starknet_types_core::felt::Felt {
        starknet_types_core::felt::Felt::from_bytes_be(&self.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_crypto::Felt;
    use pathfinder_merkle_tree::starknet_state::update_starknet_state;

    use crate::account::Account;
    use crate::{class, contract, fixtures};

    #[test]
    fn test_init_devnet() {
        use pathfinder_common::state_update::StateUpdateData;
        use pathfinder_common::{BlockNumber, StarknetVersion, StateCommitment};
        use pathfinder_storage::StorageBuilder;

        let storage = StorageBuilder::in_tempdir().unwrap();
        let mut db_conn = storage.connection().unwrap();
        let db_txn = db_conn.transaction().unwrap();
        let mut state_update = StateUpdateData::default();

        fixtures::PREDECLARED_CLASSES
            .iter()
            .copied()
            .for_each(|(class, class_hash)| {
                class::predeclare(&db_txn, &mut state_update, class, Some(class_hash)).unwrap()
            });

        fixtures::PREDEPLOYED_CONTRACTS.iter().copied().for_each(
            |(contract_address, class_hash)| {
                contract::predeploy(&mut state_update, contract_address, class_hash).unwrap()
            },
        );

        fixtures::ERC20S
            .iter()
            .copied()
            .for_each(|(contract_address, name, symbol)| {
                contract::erc20_init(&mut state_update, contract_address, name, symbol).unwrap();
            });

        [
            (
                Felt::from_u64(1 /* Keep ECDSA happy */),
                fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
                None,
            ),
            (
                fixtures::CHARGEABLE_ACCOUNT_PRIVATE_KEY,
                fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
                Some(fixtures::CHARGEABLE_ACCOUNT_ADDRESS),
            ),
        ]
        .iter()
        .copied()
        .for_each(|(private_key, class_hash, address)| {
            let account = Account::new(
                private_key,
                class_hash,
                address,
                u128::MAX,
                fixtures::ETH_ERC20_CONTRACT_ADDRESS,
                fixtures::STRK_ERC20_CONTRACT_ADDRESS,
            )
            .unwrap();
            account.predeploy(&mut state_update).unwrap();
        });

        let (storage_commitment, class_commitment) = update_starknet_state(
            &db_txn,
            (&state_update).into(),
            true,
            BlockNumber::GENESIS,
            storage.clone(),
        )
        .unwrap();
        let state_commitment = StateCommitment::calculate(
            storage_commitment,
            class_commitment,
            StarknetVersion::V_0_14_0,
        );

        db_txn
            .insert_state_update_data(BlockNumber::GENESIS, &state_update)
            .unwrap();
        db_txn.commit().unwrap();
    }
}
