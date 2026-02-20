use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::{ClassHash, ContractAddress, SierraHash, StorageAddress, StorageValue};
use pathfinder_crypto::Felt;
use pathfinder_executor::IntoFelt as _;
use starknet_api::abi::abi_utils::get_storage_var_address;

use crate::devnet::fixtures::CHARGEABLE_ACCOUNT_ADDRESS;
use crate::devnet::utils::cairo_short_string_to_felt;

pub fn predeploy(
    state_update: &mut StateUpdateData,
    contract_address: ContractAddress,
    sierra_hash: SierraHash,
) -> anyhow::Result<()> {
    let overwritten = state_update
        .contract_updates
        .insert(
            contract_address,
            pathfinder_common::state_update::ContractUpdate {
                class: Some(
                    pathfinder_common::state_update::ContractClassUpdate::Deploy(ClassHash(
                        sierra_hash.0,
                    )),
                ),
                ..Default::default()
            },
        )
        .is_some();
    anyhow::ensure!(
        !overwritten,
        "Predeploying to address {contract_address} would overwrite an existing contract update"
    );
    Ok(())
}

pub fn erc20_init(
    state_update: &mut StateUpdateData,
    contract_address: ContractAddress,
    erc20_name: &str,
    erc20_symbol: &str,
) -> anyhow::Result<()> {
    let contract_update = state_update
        .contract_updates
        .entry(contract_address)
        .or_default();

    for (storage_var_name, storage_value) in [
        ("ERC20_name", cairo_short_string_to_felt(erc20_name)?),
        ("ERC20_symbol", cairo_short_string_to_felt(erc20_symbol)?),
        ("ERC20_decimals", Felt::from_u64(18)),
        ("permitted_minter", CHARGEABLE_ACCOUNT_ADDRESS.0),
    ] {
        let storage_var_address =
            StorageAddress(get_storage_var_address(storage_var_name, &[]).into_felt());
        let storage_value = StorageValue(storage_value);
        contract_update
            .storage
            .insert(storage_var_address, storage_value);
    }

    Ok(())
}
