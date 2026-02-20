use std::sync::Arc;
use std::u128;

use anyhow::Context;
use num_bigint::BigUint;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::{
    BlockId,
    ContractAddress,
    ContractNonce,
    PublicKey,
    SierraHash,
    TransactionNonce,
};
use pathfinder_crypto::Felt;
use pathfinder_executor::{IntoFelt as _, IntoStarkFelt as _};
use starknet_api::abi::abi_utils::get_storage_var_address;

use crate::devnet::contract::predeploy;
use crate::devnet::fixtures;
use crate::devnet::utils::{get_storage_at, join_felts, set_storage_at, split_biguint};

pub struct Account {
    sierra_hash: SierraHash,
    private_key: Felt,
    public_key: PublicKey,
    address: ContractAddress,
    eth_fee_token_address: ContractAddress,
    strk_fee_token_address: ContractAddress,
    nonce: ContractNonce,
}

impl Account {
    /// Creates a new account from fixture.
    pub fn new_from_fixture() -> Self {
        Self {
            sierra_hash: fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
            private_key: fixtures::ACCOUNT_PRIVATE_KEY,
            public_key: fixtures::ACCOUNT_PUBLIC_KEY,
            address: fixtures::ACCOUNT_ADDRESS,
            eth_fee_token_address: fixtures::ETH_ERC20_CONTRACT_ADDRESS,
            strk_fee_token_address: fixtures::STRK_ERC20_CONTRACT_ADDRESS,
            nonce: ContractNonce::ZERO,
        }
    }

    /// Creates a new account from fixture and recovers its nonce from storage.
    pub fn from_storage(db_txn: &pathfinder_storage::Transaction<'_>) -> anyhow::Result<Self> {
        let mut account = Self::new_from_fixture();
        let nonce = db_txn
            .contract_nonce(account.address, BlockId::Latest)?
            // If the account has not been used before, it won't have the nonce in storage yet, so
            // we default to 0
            .unwrap_or_default();
        account.nonce = nonce;
        Ok(account)
    }

    pub fn predeploy(&self, state_update: &mut StateUpdateData) -> anyhow::Result<()> {
        predeploy(state_update, self.address, self.sierra_hash)?;
        self.set_initial_balance(state_update)?;
        self.simulate_constructor(state_update)
    }

    pub fn address(&self) -> ContractAddress {
        self.address
    }

    pub fn private_key(&self) -> Felt {
        self.private_key
    }

    pub fn fetch_add_nonce(&mut self) -> TransactionNonce {
        let nonce = self.nonce;
        self.nonce = ContractNonce(self.nonce.0 + Felt::ONE);
        TransactionNonce(nonce.0)
    }

    /// Sets initial balance to u128::MAX
    fn set_initial_balance(&self, state_update: &mut StateUpdateData) -> anyhow::Result<()> {
        let initial_balance = u128::MAX;
        let storage_var_address_low: starknet_api::state::StorageKey =
            get_storage_var_address("ERC20_balances", &[self.address.0.into_starkfelt()]);
        let storage_var_address_high = storage_var_address_low.next_storage_key()?;

        let total_supply_storage_address_low: starknet_api::state::StorageKey =
            get_storage_var_address("ERC20_total_supply", &[]);
        let total_supply_storage_address_high =
            total_supply_storage_address_low.next_storage_key()?;

        let (high, low) = split_biguint(BigUint::from(initial_balance));

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

            let new_total_supply =
                join_felts(total_supply_high, total_supply_low) + BigUint::from(initial_balance);

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
