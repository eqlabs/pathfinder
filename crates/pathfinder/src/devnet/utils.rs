use anyhow::Context as _;
use num_bigint::BigUint;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::{ContractAddress, StorageAddress, StorageValue};
use pathfinder_crypto::Felt;
use pathfinder_executor::IntoFelt as _;

/// Converts Cairo short string to [`Felt`].
pub fn cairo_short_string_to_felt(str: &str) -> anyhow::Result<Felt> {
    anyhow::ensure!(
        str.is_ascii(),
        "Cairo short strings must be ASCII, but got: {str}"
    );
    anyhow::ensure!(
        str.len() <= 31,
        "Cairo short strings must be at most 31 characters long, but got a string of length {}: \
         {str}",
        str.len()
    );

    let ascii_bytes = str.as_bytes();

    let mut buffer = [0u8; 32];
    buffer[(32 - ascii_bytes.len())..].copy_from_slice(ascii_bytes);

    Ok(Felt::from_be_bytes(buffer).expect("not to overflow"))
}

pub fn split_biguint(biguint: BigUint) -> (Felt, Felt) {
    let high: BigUint = &biguint >> 128;
    let high = Felt::from_u128(high.try_into().expect("no overflow"));
    let low_mask = (BigUint::from(1_u8) << 128) - 1_u8;
    let low: BigUint = &biguint & &low_mask;
    let low = Felt::from_u128(low.try_into().expect("no overflow"));
    (high, low)
}

pub fn join_felts(high: Felt, low: Felt) -> BigUint {
    let high: u128 = high.try_into().expect("no overflow");
    let high = BigUint::from(high);
    let low: u128 = low.try_into().expect("no overflow");
    let low = BigUint::from(low);

    (high << 128) + low
}

pub fn get_storage_at(
    state_update: &StateUpdateData,
    contract_address: ContractAddress,
    storage_address: starknet_api::state::StorageKey,
) -> Felt {
    state_update
        .contract_updates
        .get(&contract_address)
        .and_then(|update| {
            update
                .storage
                .get(&StorageAddress(storage_address.into_felt()))
        })
        .map(|storage_value| storage_value.0)
        .unwrap_or_default()
}

pub fn set_storage_at(
    state_update: &mut StateUpdateData,
    contract_address: ContractAddress,
    storage_address: starknet_api::state::StorageKey,
    value: Felt,
) -> anyhow::Result<()> {
    let contract_update = state_update
        .contract_updates
        .get_mut(&contract_address)
        .context("Contract not found in state update")?;
    contract_update.storage.insert(
        StorageAddress(storage_address.into_felt()),
        StorageValue(value),
    );
    Ok(())
}
