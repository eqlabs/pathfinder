use std::sync::atomic::{AtomicU64, Ordering};
use std::u128;

use num_bigint::BigUint;
use p2p::sync::client::conv::ToDto as _;
use p2p_proto::common::Hash;
use pathfinder_common::state_update::StateUpdateData;
use pathfinder_common::transaction::{
    DataAvailabilityMode,
    InvokeTransactionV3,
    TransactionVariant,
};
use pathfinder_common::{
    entry_point,
    BlockId,
    CallParam,
    ChainId,
    ContractAddress,
    EntryPoint,
    PublicKey,
    SierraHash,
    Tip,
    TransactionNonce,
    TransactionSignatureElem,
};
use pathfinder_crypto::signature::ecdsa_sign;
use pathfinder_crypto::Felt;
use pathfinder_executor::IntoStarkFelt as _;
use starknet_api::abi::abi_utils::get_storage_var_address;

use crate::devnet::contract::predeploy;
use crate::devnet::fixtures;
use crate::devnet::fixtures::RESOURCE_BOUNDS;
use crate::devnet::utils::{get_storage_at, join_felts, set_storage_at, split_biguint};

pub struct Account {
    sierra_hash: SierraHash,
    private_key: Felt,
    public_key: PublicKey,
    address: ContractAddress,
    eth_fee_token_address: ContractAddress,
    strk_fee_token_address: ContractAddress,
    // Account nonce
    nonce: AtomicU64,
    /// Used for consecutive hello_starknet deployments to avoid address
    /// collisions
    deployment_salt: AtomicU64,
    /// Hello starknet deployments so far.
    deployed: Vec<ContractAddress>,
}

impl Account {
    /// Creates a new account from fixture.
    pub(super) fn new_from_fixture() -> Self {
        Self {
            sierra_hash: fixtures::CAIRO_1_ACCOUNT_CLASS_HASH,
            private_key: fixtures::ACCOUNT_PRIVATE_KEY,
            public_key: fixtures::ACCOUNT_PUBLIC_KEY,
            address: fixtures::ACCOUNT_ADDRESS,
            eth_fee_token_address: fixtures::ETH_ERC20_CONTRACT_ADDRESS,
            strk_fee_token_address: fixtures::STRK_ERC20_CONTRACT_ADDRESS,
            nonce: AtomicU64::new(0),
            deployment_salt: AtomicU64::new(0),
            deployed: Vec::new(),
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
        let nonce_bytes = nonce.0.as_be_bytes();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&nonce_bytes[24..]);
        account.nonce = AtomicU64::new(u64::from_be_bytes(buf));
        Ok(account)
    }

    pub(super) fn predeploy(&self, state_update: &mut StateUpdateData) -> anyhow::Result<()> {
        predeploy(state_update, self.address, self.sierra_hash)?;
        self.set_initial_balance(state_update)?;
        self.simulate_constructor(state_update)
    }

    pub(super) fn address(&self) -> ContractAddress {
        self.address
    }

    pub(super) fn private_key(&self) -> Felt {
        self.private_key
    }

    pub(super) fn fetch_add_nonce(&self) -> TransactionNonce {
        TransactionNonce(Felt::from_u64(self.nonce.fetch_add(1, Ordering::Relaxed)))
    }

    fn fetch_add_deployment_salt(&self) -> CallParam {
        CallParam(Felt::from_u64(
            self.deployment_salt.fetch_add(1, Ordering::Relaxed),
        ))
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

    /// Create an invoke transaction deploying another instance of hello
    /// starknet contract
    pub fn hello_starknet_deploy(&self) -> anyhow::Result<p2p_proto::consensus::Transaction> {
        // Calldata structure for deployment via InvokeV3:
        // https://github.com/software-mansion/starknet-rust/blob/8c6e5eef7b2b19256ee643eefe742119188092e6/starknet-rust-accounts/src/single_owner.rs#L141
        //
        // Calldata structure for UDC:
        // https://docs.openzeppelin.com/contracts-cairo/2.x/udc
        // https://github.com/OpenZeppelin/cairo-contracts/blob/802735d432499124c684d28a5a0465ebf6c9cbdb/packages/presets/src/universal_deployer.cairo#L46
        //
        // "calldata": [
        //     /* Number of calls */
        //     "0x1",
        //     /* UDC address */
        //     "0x2ceed65a4bd731034c01113685c831b01c15d7d432f71afb1cf1634b53a2125",
        //     /* Selector for 'deployContract' */
        //     "0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d",
        //     /* Calldata length */
        //     "0x4",
        //     /* UDC Calldata - class hash */
        //     "0x0457EF47CFAA819D9FE1372E8957815CDBA2252ED3E42A15536A5A40747C8A00",
        //     /* UDC Calldata - salt */
        //     "0x0",
        //     /* UDC Calldata - not_from_zero, 0 for origin independent deployment */
        //     "0x0",
        //     /* UDC Calldata - calldata to pass to the target contract */
        //     "0x0"
        // ],

        let selector = EntryPoint::hashed(b"deployContract");
        assert_eq!(
            selector,
            entry_point!("0x1987cbd17808b9a23693d4de7e246a443cfe37e6e7fbaeabd7d7e6532b07c3d")
        );

        let invoke = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: self.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: fixtures::RESOURCE_BOUNDS,
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // UDC address
                CallParam(fixtures::UDC_CONTRACT_ADDRESS.0),
                // Selector for 'deployContract'
                CallParam(selector.0),
                // Calldata length
                CallParam(Felt::from_u64(4)),
                // UDC Calldata - class hash
                CallParam(fixtures::HELLO_CLASS_HASH.0),
                // UDC Calldata - salt
                self.fetch_add_deployment_salt(),
                // UDC Calldata - not_from_zero, 0 for origin independent deployment
                CallParam::ZERO,
                // UDC Calldata - calldata to pass to the target contract
                CallParam::ZERO,
            ],
            sender_address: self.address(),
            proof_facts: vec![],
        };

        let mut variant = TransactionVariant::InvokeV3(invoke);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(self.private_key(), txn_hash.0)?;
        let TransactionVariant::InvokeV3(invoke) = &mut variant else {
            unreachable!();
        };
        invoke.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(invoke) = variant else {
            unreachable!();
        };

        Ok(p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(invoke),
            transaction_hash: Hash(txn_hash.0),
        })
    }

    /// Create an invoke transaction that calls increase_balance function of a
    /// hello starknet contract instance
    pub fn hello_starknet_increase_balance(
        &self,
        contract_address: ContractAddress,
    ) -> p2p_proto::consensus::Transaction {
        let selector = EntryPoint::hashed(b"increase_balance");
        assert_eq!(
            selector,
            entry_point!("0x362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320")
        );

        let invoke = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: self.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: RESOURCE_BOUNDS,
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // Hello contract address
                CallParam(contract_address.0),
                // Selector for 'increase_balance'
                CallParam(selector.0),
                // Calldata length
                CallParam(Felt::ONE),
                // Hello starknet increase_balance argument
                CallParam(Felt::from_u64(0xFF)),
            ],
            sender_address: self.address(),
            proof_facts: vec![],
        };

        eprintln!("Invoke transaction: {invoke:#?}");

        let mut variant = TransactionVariant::InvokeV3(invoke);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(self.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(invoke) = &mut variant else {
            unreachable!();
        };
        invoke.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(invoke) = variant else {
            unreachable!();
        };

        p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(invoke),
            transaction_hash: Hash(txn_hash.0),
        }
    }

    /// Create an invoke transaction that calls get_balance function of a hello
    /// starknet contract instance
    pub fn hello_starknet_get_balance(
        &self,
        contract_address: ContractAddress,
    ) -> p2p_proto::consensus::Transaction {
        let selector = EntryPoint::hashed(b"get_balance");
        assert_eq!(
            selector,
            entry_point!("0x39e11d48192e4333233c7eb19d10ad67c362bb28580c604d67884c85da39695")
        );

        let invoke = InvokeTransactionV3 {
            signature: vec![/* Will be filled after signing */],
            nonce: self.fetch_add_nonce(),
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            resource_bounds: RESOURCE_BOUNDS,
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            calldata: vec![
                // Number of calls
                CallParam(Felt::ONE),
                // Hello contract address
                CallParam(contract_address.0),
                // Selector for 'get_balance'
                CallParam(selector.0),
                // Calldata length
                CallParam(Felt::ZERO),
            ],
            sender_address: self.address(),
            proof_facts: vec![],
        };

        let mut variant = TransactionVariant::InvokeV3(invoke);
        let txn_hash = variant.calculate_hash(ChainId::SEPOLIA_TESTNET, false);
        let (r, s) = ecdsa_sign(self.private_key(), txn_hash.0).unwrap();
        let TransactionVariant::InvokeV3(invoke) = &mut variant else {
            unreachable!();
        };
        invoke.signature = vec![TransactionSignatureElem(r), TransactionSignatureElem(s)];

        let variant = variant.to_dto();

        let p2p_proto::sync::transaction::TransactionVariant::InvokeV3(invoke) = variant else {
            unreachable!();
        };

        p2p_proto::consensus::Transaction {
            txn: p2p_proto::consensus::TransactionVariant::InvokeV3(invoke),
            transaction_hash: Hash(txn_hash.0),
        }
    }
}
