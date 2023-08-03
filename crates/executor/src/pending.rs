use blockifier::state::errors::StateError;
use pathfinder_common::state_update::{ContractUpdate, SystemContractUpdate};
use pathfinder_common::StateUpdate;
use primitive_types::U256;
use starknet_api::core::{ContractAddress, PatriciaKey};
use starknet_api::state::StorageKey;

use super::felt::IntoStarkFelt;

pub(crate) fn apply_pending_update<S: blockifier::state::state_api::State>(
    state: &mut S,
    pending_update: &StateUpdate,
) -> Result<(), StateError> {
    // NOTE: class _declarations_ are handled during sync. We download and insert new class declarations for the pending block
    // after downloading it -- here we build on the fact that those are already available in the database -- and thus in the state
    // as well...
    for (
        contract_address,
        ContractUpdate {
            storage,
            class,
            nonce,
        },
    ) in &pending_update.contract_updates
    {
        let address = ContractAddress(PatriciaKey::try_from(
            contract_address.get().into_starkfelt(),
        )?);

        for (key, value) in storage {
            let key = StorageKey(PatriciaKey::try_from(key.get().into_starkfelt())?);
            let value = value.0.into_starkfelt();
            state.set_storage_at(address, key, value);
        }

        if let Some(class) = class {
            use pathfinder_common::state_update::ContractClassUpdate::*;
            match class {
                Deploy(class_hash) | Replace(class_hash) => {
                    let class_hash = starknet_api::core::ClassHash(class_hash.0.into_starkfelt());
                    state.set_class_hash_at(address, class_hash)?;
                }
            };
        }

        if let Some(nonce) = nonce {
            let current_nonce = state.get_nonce_at(address)?;
            let current_nonce = U256::from_big_endian(current_nonce.0.bytes());

            let nonce = U256::from_big_endian(nonce.0.as_be_bytes());

            if nonce > current_nonce {
                let diff = nonce - current_nonce;
                let diff = diff.as_u64();

                for _ in 0..diff {
                    state.increment_nonce(address)?;
                }
            } else {
                tracing::error!(%contract_address, %current_nonce, %nonce, "Invalid nonce update in pending update");
                return Err(StateError::StateReadError(format!(
                    "Invalid nonce update in pending block for contract {}",
                    contract_address
                )));
            }
        }
    }

    for (contract_address, SystemContractUpdate { storage }) in
        &pending_update.system_contract_updates
    {
        let address = ContractAddress(PatriciaKey::try_from(
            contract_address.get().into_starkfelt(),
        )?);

        for (key, value) in storage {
            let key = StorageKey(PatriciaKey::try_from(key.get().into_starkfelt())?);
            let value = value.0.into_starkfelt();
            state.set_storage_at(address, key, value);
        }
    }

    Ok(())
}
