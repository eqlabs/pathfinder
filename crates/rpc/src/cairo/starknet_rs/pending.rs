use std::collections::HashMap;

use pathfinder_common::state_update::{ContractUpdate, SystemContractUpdate};
use pathfinder_common::StateUpdate;
use starknet_in_rust::core::errors::state_errors::StateError;
use starknet_in_rust::felt::Felt252;
use starknet_in_rust::utils::Address;

use super::felt::IntoFelt252;

pub(crate) fn apply_pending_update<S: starknet_in_rust::state::state_api::State>(
    state: &mut S,
    pending_update: &StateUpdate,
) -> Result<(), StateError> {
    // NOTE: class _declarations_ are handled during sync. We download and insert new class declarations for the pending block
    // after downloading it -- here we build on the fact that those are already available in the database -- and thus in the state
    // as well...

    let mut address_to_class_hash: HashMap<Address, starknet_in_rust::utils::ClassHash> =
        Default::default();
    let mut address_to_nonce: HashMap<Address, Felt252> = Default::default();
    let mut storage_updates: HashMap<Address, HashMap<Felt252, Felt252>> = Default::default();

    for (
        contract_address,
        ContractUpdate {
            storage,
            class,
            nonce,
        },
    ) in &pending_update.contract_updates
    {
        let contract_address = Address(contract_address.get().into_felt252());

        let diff: HashMap<Felt252, Felt252> = storage
            .iter()
            .map(|(address, value)| (address.get().into_felt252(), value.0.into_felt252()))
            .collect();

        if !diff.is_empty() {
            storage_updates.insert(contract_address.clone(), diff);
        }

        if let Some(class) = class {
            use pathfinder_common::state_update::ContractClassUpdate::*;
            match class {
                Deploy(class_hash) | Replace(class_hash) => {
                    address_to_class_hash
                        .insert(contract_address.clone(), class_hash.0.to_be_bytes());
                }
            };
        }

        if let Some(nonce) = nonce {
            address_to_nonce.insert(contract_address, nonce.0.into_felt252());
        }
    }

    for (contract_address, SystemContractUpdate { storage }) in
        &pending_update.system_contract_updates
    {
        let contract_address = Address(contract_address.get().into_felt252());

        let diff: HashMap<Felt252, Felt252> = storage
            .iter()
            .map(|(address, value)| (address.get().into_felt252(), value.0.into_felt252()))
            .collect();

        if !diff.is_empty() {
            storage_updates.insert(contract_address.clone(), diff);
        }
    }

    state.apply_state_update(&starknet_in_rust::state::StateDiff::new(
        address_to_class_hash,
        address_to_nonce,
        Default::default(),
        storage_updates,
    ))
}
