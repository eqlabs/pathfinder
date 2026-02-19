use std::sync::Arc;

use anyhow::Context;
use num_bigint::BigUint;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::{ClassHash, ContractAddress, PublicKey, TransactionNonce};
use pathfinder_crypto::Felt;
use pathfinder_executor::{IntoFelt as _, IntoStarkFelt as _};
use starknet_api::abi::abi_utils::get_storage_var_address;
use starknet_api::core::calculate_contract_address;

use crate::devnet::contract::predeploy;
use crate::devnet::fixtures;
use crate::devnet::utils::{get_storage_at, join_felts, set_storage_at, split_biguint};

pub struct Account {
    class_hash: ClassHash,
    private_key: Felt,
    public_key: PublicKey,
    address: ContractAddress,
    initial_balance: u128,
    eth_fee_token_address: ContractAddress,
    strk_fee_token_address: ContractAddress,
    nonce: u64,
}

impl Account {
    /// Creates a new account with the given private key, class hash, and
    /// optional address. If the address is not provided, it will be calculated
    /// using the class hash, public key derived from the private key, and a
    /// default salt.
    pub fn new(
        private_key: Felt,
        class_hash: ClassHash,
        address: Option<ContractAddress>,
        initial_balance: u128,
        eth_fee_token_address: ContractAddress,
        strk_fee_token_address: ContractAddress,
    ) -> anyhow::Result<Self> {
        let public_key = pathfinder_crypto::signature::get_pk(private_key)
            .context("Failed to derive public key")?;

        let public_key = PublicKey(public_key);
        let address = if let Some(address) = address {
            address
        } else {
            ContractAddress(
                calculate_contract_address(
                    // Is this necessary?
                    // starknet_api::transaction::fields::ContractAddressSalt(
                    //     starknet_rust_core::types::Felt::from_hex("0x14").unwrap(),
                    // ),
                    Default::default(),
                    starknet_api::core::ClassHash(class_hash.0.into_starkfelt()),
                    &starknet_api::transaction::fields::Calldata(Arc::new(vec![public_key
                        .0
                        .into_starkfelt()])),
                    Default::default(),
                )?
                .into_felt(),
            )
        };

        Ok(Self {
            class_hash,
            private_key,
            public_key,
            address,
            initial_balance,
            eth_fee_token_address,
            strk_fee_token_address,
            nonce: 0,
        })
    }

    pub fn predeploy(&self, state_update: &mut StateUpdateData) -> anyhow::Result<()> {
        predeploy(state_update, self.address, self.class_hash)?;
        self.set_initial_balance(state_update)?;
        self.simulate_constructor(state_update)
    }

    pub fn address(&self) -> ContractAddress {
        self.address
    }

    pub fn secret_key(&self) -> Felt {
        self.private_key
    }

    pub fn fetch_add_nonce(&mut self) -> TransactionNonce {
        let nonce = self.nonce;
        self.nonce += 1;
        TransactionNonce(Felt::from(nonce))
    }

    fn set_initial_balance(&self, state_update: &mut StateUpdateData) -> anyhow::Result<()> {
        let storage_var_address_low: starknet_api::state::StorageKey =
            get_storage_var_address("ERC20_balances", &[self.address.0.into_starkfelt()]);
        let storage_var_address_high = storage_var_address_low.next_storage_key()?;

        let total_supply_storage_address_low: starknet_api::state::StorageKey =
            get_storage_var_address("ERC20_total_supply", &[]);
        let total_supply_storage_address_high =
            total_supply_storage_address_low.next_storage_key()?;

        let (high, low) = split_biguint(BigUint::from(self.initial_balance));

        for fee_token_address in [self.eth_fee_token_address, self.strk_fee_token_address] {
            let token_address = fee_token_address.into();

            let total_supply_low = get_storage_at(
                state_update,
                token_address,
                total_supply_storage_address_low,
            );
            let total_supply_high = get_storage_at(
                state_update,
                token_address,
                total_supply_storage_address_high,
            );

            let new_total_supply = join_felts(total_supply_high, total_supply_low)
                + BigUint::from(self.initial_balance);

            let (new_total_supply_high, new_total_supply_low) = split_biguint(new_total_supply);

            // set balance in ERC20_balances
            set_storage_at(state_update, token_address, storage_var_address_low, low)?;
            set_storage_at(state_update, token_address, storage_var_address_high, high)?;

            // set total supply in ERC20_total_supply
            set_storage_at(
                state_update,
                token_address,
                total_supply_storage_address_low,
                new_total_supply_low,
            )?;

            set_storage_at(
                state_update,
                token_address,
                total_supply_storage_address_high,
                new_total_supply_high,
            )?;
        }

        Ok(())
    }

    // Simulate constructor logic (register interfaces and set public key), as done
    // in https://github.com/OpenZeppelin/cairo-contracts/blob/89a450a88628ec3b86273f261b2d8d1ca9b1522b/src/account/account.cairo#L207-L211
    fn simulate_constructor(&self, state_update: &mut StateUpdateData) -> anyhow::Result<()> {
        let interface_storage_var = get_storage_var_address(
            "SRC5_supported_interfaces",
            &[fixtures::ISRC6_ID.into_starkfelt()],
        );
        set_storage_at(
            state_update,
            self.address,
            interface_storage_var.into(),
            Felt::ONE,
        )?;

        let public_key_storage_var = get_storage_var_address("Account_public_key", &[]);
        set_storage_at(
            state_update,
            self.address,
            public_key_storage_var.into(),
            self.public_key.0,
        )?;

        Ok(())
    }
}
