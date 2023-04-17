use std::collections::HashMap;

use anyhow::Context;
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_vm::felt::Felt252;
use ethers::types::U256;
use pathfinder_common::{
    CallParam, CallResultValue, CasmHash, ChainId, ClassHash, ContractAddress, EntryPoint,
    StorageAddress, StorageCommitment,
};
use pathfinder_merkle_tree::{ContractsStorageTree, StorageCommitmentTree};
use pathfinder_storage::{CasmClassTable, ContractCodeTable, ContractsStateTable};
use stark_hash::Felt;
use starknet_rs::business_logic::execution::execution_entry_point::ExecutionEntryPoint;
use starknet_rs::business_logic::execution::objects::{
    TransactionExecutionContext, TransactionExecutionInfo,
};
use starknet_rs::business_logic::fact_state::state::ExecutionResourcesManager;
use starknet_rs::business_logic::state::cached_state::CachedState;
use starknet_rs::business_logic::state::state_api::{State, StateReader};
use starknet_rs::business_logic::transaction::error::TransactionError;
use starknet_rs::business_logic::transaction::objects::{
    internal_declare::InternalDeclare, internal_deploy_account::InternalDeployAccount,
    internal_invoke_function::InternalInvokeFunction, v2::declare_v2::InternalDeclareV2,
};
use starknet_rs::core::errors::state_errors::StateError;
use starknet_rs::definitions::general_config::{StarknetGeneralConfig, StarknetOsConfig};
use starknet_rs::services::api::contract_classes::compiled_class::CompiledClass;
use starknet_rs::services::api::contract_classes::deprecated_contract_class::ContractClass;
use starknet_rs::starknet_storage::errors::storage_errors::StorageError;

use crate::v02::types::request::BroadcastedTransaction;

pub(crate) enum CallError {
    ContractNotFound,
    InvalidMessageSelector,
    Internal(anyhow::Error),
}

impl From<TransactionError> for CallError {
    fn from(value: starknet_rs::business_logic::transaction::error::TransactionError) -> Self {
        match value {
            TransactionError::EntryPointNotFound => Self::InvalidMessageSelector,
            TransactionError::FailToReadClassHash => Self::ContractNotFound,
            e => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
        }
    }
}

impl From<anyhow::Error> for CallError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}

pub(crate) fn call(
    storage: pathfinder_storage::Storage,
    storage_commitment: StorageCommitment,
    contract_address: ContractAddress,
    entry_point_selector: EntryPoint,
    calldata: Vec<CallParam>,
) -> Result<Vec<CallResultValue>, CallError> {
    let state_reader = SqliteReader {
        storage: storage,
        storage_commitment,
    };

    let contract_class_cache = HashMap::new();
    let casm_class_cache = HashMap::new();
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_class_cache),
    );

    let contract_address =
        starknet_rs::utils::Address(Felt252::from_bytes_be(contract_address.get().as_be_bytes()));
    let calldata = calldata
        .iter()
        .map(|p| Felt252::from_bytes_be(p.0.as_be_bytes()))
        .collect();
    let entry_point_selector = Felt252::from_bytes_be(entry_point_selector.0.as_be_bytes());
    let caller_address = starknet_rs::utils::Address(0.into());
    let exec_entry_point = ExecutionEntryPoint::new(
        contract_address,
        calldata,
        entry_point_selector,
        caller_address.clone(),
        starknet_rs::services::api::contract_classes::deprecated_contract_class::EntryPointType::External,
        None,
        None,
        0,
    );

    let general_config = StarknetGeneralConfig::default();
    let execution_context = TransactionExecutionContext::new(
        caller_address,
        0.into(),
        Vec::new(),
        0,
        1.into(),
        general_config.invoke_tx_max_n_steps(),
        starknet_rs::definitions::constants::TRANSACTION_VERSION,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    let call_info = exec_entry_point.execute(
        &mut state,
        &general_config,
        &mut resources_manager,
        &execution_context,
        false,
    )?;

    let result = call_info
        .retdata
        .iter()
        .map(|f| Felt::from_be_slice(&f.to_bytes_be()).map(CallResultValue))
        .collect::<Result<Vec<CallResultValue>, _>>()
        .context("Converting results to felts")?;

    Ok(result)
}

pub(crate) struct FeeEstimate {
    pub gas_consumed: U256,
    pub gas_price: U256,
    pub overall_fee: U256,
}

pub(crate) fn estimate_fee(
    storage: pathfinder_storage::Storage,
    storage_commitment: StorageCommitment,
    transactions: Vec<BroadcastedTransaction>,
    chain_id: ChainId,
    gas_price: U256,
) -> Result<Vec<FeeEstimate>, CallError> {
    let transactions = transactions
        .into_iter()
        .map(|tx| map_transaction(tx, chain_id))
        .collect::<Result<Vec<_>, TransactionError>>()?;

    let state_reader = SqliteReader {
        storage: storage,
        storage_commitment,
    };

    let contract_class_cache = HashMap::new();
    let casm_class_cache = HashMap::new();
    let mut state = CachedState::new(
        state_reader,
        Some(contract_class_cache),
        Some(casm_class_cache),
    );

    let chain_id = match chain_id {
        ChainId::MAINNET => starknet_rs::definitions::general_config::StarknetChainId::MainNet,
        ChainId::TESTNET => starknet_rs::definitions::general_config::StarknetChainId::TestNet,
        ChainId::TESTNET2 => starknet_rs::definitions::general_config::StarknetChainId::TestNet2,
        _ => return Err(anyhow::anyhow!("Unsupported chain id").into()),
    };

    let starknet_os_config = StarknetOsConfig::new(
        chain_id,
        starknet_rs::utils::Address(0.into()),
        gas_price.as_u128(),
    );
    let mut general_config = StarknetGeneralConfig::default();
    // FIXME: set up block_info
    *general_config.starknet_os_config_mut() = starknet_os_config;
    general_config.block_info_mut().gas_price = gas_price.as_u64();

    let mut fees = Vec::new();

    for transaction in &transactions {
        let tx_info = transaction.execute(&mut state, &general_config)?;
        fees.push(FeeEstimate {
            gas_consumed: U256::from(tx_info.actual_fee) / std::cmp::max(1.into(), gas_price),
            gas_price,
            overall_fee: tx_info.actual_fee.into(),
        });
    }

    Ok(fees)
}

enum Transaction {
    Declare(InternalDeclare),
    DeclareV2(InternalDeclareV2),
    DeployAccount(InternalDeployAccount),
    Invoke(InternalInvokeFunction),
}

impl Transaction {
    pub fn execute<S: State + StateReader>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        match self {
            Transaction::Declare(tx) => tx.execute(state, general_config, true),
            Transaction::DeclareV2(tx) => tx.execute(state, general_config, tx.max_fee),
            Transaction::DeployAccount(tx) => tx.execute(state, general_config),
            Transaction::Invoke(tx) => tx.execute(state, general_config, true),
        }
    }
}

fn map_transaction(
    transaction: BroadcastedTransaction,
    chain_id: ChainId,
) -> Result<Transaction, TransactionError> {
    use starknet_rs::utils::Address;

    match transaction {
        BroadcastedTransaction::Declare(tx) => match tx {
            crate::v02::types::request::BroadcastedDeclareTransaction::V1(tx) => {
                let signature = tx.signature.into_iter().map(|s| s.0.into()).collect();

                // decode program
                let contract_class_json = tx
                    .contract_class
                    .serialize_to_json()
                    .map_err(|_| TransactionError::MissingCompiledClass)?;

                let contract_class =
                    ContractClass::try_from(String::from_utf8_lossy(&contract_class_json).as_ref())
                        .map_err(|_| TransactionError::MissingCompiledClass)?;

                let tx = InternalDeclare::new(
                    contract_class,
                    chain_id.0.into(),
                    Address(tx.sender_address.get().into()),
                    // FIXME: we're truncating to lower 128 bits
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    // FIXME: we're truncating to lower 128 bits
                    u64::from_be_bytes(tx.version.0.as_bytes()[24..].try_into().unwrap()),
                    signature,
                    tx.nonce.0.into(),
                    None,
                )?;
                Ok(Transaction::Declare(tx))
            }
            crate::v02::types::request::BroadcastedDeclareTransaction::V2(tx) => {
                let signature = tx.signature.into_iter().map(|s| s.0.into()).collect();

                let json = serde_json::json!({
                    "abi": [],
                    "sierra_program": tx.contract_class.sierra_program,
                    "contract_class_version": tx.contract_class.contract_class_version,
                    "entry_points_by_type": tx.contract_class.entry_points_by_type,
                });

                let contract_class = serde_json::from_value::<SierraContractClass>(json)
                    .map_err(|_| TransactionError::MissingCompiledClass)?;

                let tx = InternalDeclareV2::new(
                    &contract_class,
                    tx.compiled_class_hash.0.into(),
                    chain_id.0.into(),
                    Address(tx.sender_address.get().into()),
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    u64::from_be_bytes(tx.version.0.as_bytes()[24..].try_into().unwrap()),
                    signature,
                    tx.nonce.0.into(),
                    None,
                )?;

                Ok(Transaction::DeclareV2(tx))
            }
        },
        BroadcastedTransaction::Invoke(tx) => match tx {
            crate::v02::types::request::BroadcastedInvokeTransaction::V1(tx) => {
                let calldata = tx.calldata.into_iter().map(|p| p.0.into()).collect();
                let signature = tx.signature.into_iter().map(|s| s.0.into()).collect();
                let tx = InternalInvokeFunction::new(
                    Address(tx.sender_address.get().into()),
                    starknet_rs::definitions::constants::EXECUTE_ENTRY_POINT_SELECTOR.clone(),
                    // FIXME: we're truncating to lower 64 bits
                    u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                    calldata,
                    signature,
                    chain_id.0.into(),
                    Some(tx.nonce.0.into()),
                    None,
                )?;
                Ok(Transaction::Invoke(tx))
            }
        },
        BroadcastedTransaction::DeployAccount(tx) => {
            let constructor_calldata = tx
                .constructor_calldata
                .into_iter()
                .map(|p| p.0.into())
                .collect();
            let signature = tx.signature.into_iter().map(|s| s.0.into()).collect();
            let tx = InternalDeployAccount::new(
                tx.class_hash.0.to_be_bytes(),
                // FIXME: we're truncating to lower 64 bits
                u128::from_be_bytes(tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap()),
                // FIXME: we're truncating to lower 64 bits
                u64::from_be_bytes(tx.version.0.as_bytes()[24..].try_into().unwrap()),
                tx.nonce.0.into(),
                constructor_calldata,
                signature,
                Address(tx.contract_address_salt.0.into()),
                chain_id.0.into(),
                None,
            )?;
            Ok(Transaction::DeployAccount(tx))
        }
    }
}

#[derive(Clone)]
struct SqliteReader {
    pub storage: pathfinder_storage::Storage,
    pub storage_commitment: StorageCommitment,
}

impl StateReader for SqliteReader {
    fn get_contract_class(
        &mut self,
        class_hash: &starknet_rs::utils::ClassHash,
    ) -> Result<ContractClass, StateError> {
        let class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let definition =
            ContractCodeTable::get_class_raw(&tx, class_hash).map_err(map_anyhow_to_state_err)?;

        match definition {
            Some(definition) => {
                let definition = String::from_utf8(definition)
                    .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;

                let contract_class = definition
                    .as_str()
                    .try_into()
                    .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;

                Ok(contract_class)
            }
            None => Err(StateError::MissingClassHash()),
        }
    }

    fn get_class_hash_at(
        &mut self,
        contract_address: &starknet_rs::utils::Address,
    ) -> Result<starknet_rs::utils::ClassHash, starknet_rs::core::errors::state_errors::StateError>
    {
        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let tree = StorageCommitmentTree::load(&tx, self.storage_commitment);
        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );
        let state_hash = tree
            .get(pathfinder_contract_address)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;

        use rusqlite::OptionalExtension;

        let class_hash: Option<ClassHash> = tx
            .query_row(
                "SELECT hash FROM contract_states WHERE state_hash=?",
                [state_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;

        let class_hash =
            class_hash.ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?;

        Ok(class_hash.0.to_be_bytes())
    }

    fn get_nonce_at(
        &mut self,
        contract_address: &starknet_rs::utils::Address,
    ) -> Result<cairo_vm::felt::Felt252, starknet_rs::core::errors::state_errors::StateError> {
        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let tree = StorageCommitmentTree::load(&tx, self.storage_commitment);

        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );
        let state_hash = tree
            .get(pathfinder_contract_address)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?
            .ok_or_else(|| StateError::ContractAddressUnavailable(contract_address.clone()))?;

        let nonce = ContractsStateTable::get_nonce(&tx, state_hash)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?
            .ok_or_else(|| StateError::ContractAddressUnavailable(contract_address.clone()))?;

        Ok(nonce.0.into())
    }

    fn get_storage_at(
        &mut self,
        storage_entry: &starknet_rs::business_logic::state::state_cache::StorageEntry,
    ) -> Result<cairo_vm::felt::Felt252, starknet_rs::core::errors::state_errors::StateError> {
        let (contract_address, storage_key) = storage_entry;
        let storage_key =
            StorageAddress::new(Felt::from_be_slice(storage_key).map_err(|_| {
                StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
            })?)
            .ok_or_else(|| {
                StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
            })?;

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let tree = StorageCommitmentTree::load(&tx, self.storage_commitment);

        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );
        let state_hash = tree
            .get(pathfinder_contract_address)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?
            .ok_or_else(|| StateError::ContractAddressUnavailable(contract_address.clone()))?;

        let contract_state_root = ContractsStateTable::get_root(&tx, state_hash)
            .map_err(|_| StateError::NoneContractState(contract_address.clone()))?
            .ok_or_else(|| StateError::NoneContractState(contract_address.clone()))?;

        let contract_state_tree = ContractsStorageTree::load(&tx, contract_state_root);

        let storage_val = contract_state_tree
            .get(storage_key)
            .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()))?;

        Ok(storage_val.0.into())
    }

    fn count_actual_storage_changes(&mut self) -> (usize, usize) {
        // read-only storage
        (0, 0)
    }

    fn get_compiled_class(
        &mut self,
        compiled_class_hash: &starknet_rs::utils::CompiledClassHash,
    ) -> Result<CompiledClass, StateError> {
        // compiled_class_hash is _either_ a "Deprecated" class hash _or_ a CASM hash
        let compiled_class_hash =
            CasmHash(Felt::from_be_slice(compiled_class_hash).expect("Overflow in class hash"));

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        if let Some(casm_definition) = CasmClassTable::get_class_raw(&tx, compiled_class_hash)
            .map_err(map_anyhow_to_state_err)?
        {
            let casm_class: cairo_lang_starknet::casm_contract_class::CasmContractClass =
                serde_json::from_slice(&casm_definition)
                    .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;
            return Ok(CompiledClass::Casm(casm_class.into()));
        }

        let class_hash = ClassHash(compiled_class_hash.0);
        if let Some(definition) =
            ContractCodeTable::get_class_raw(&tx, class_hash).map_err(map_anyhow_to_state_err)?
        {
            let definition = String::from_utf8(definition)
                .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;

            let contract_class: ContractClass = definition
                .as_str()
                .try_into()
                .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?;

            return Ok(CompiledClass::Deprecated(contract_class.into()));
        }

        Err(StateError::Storage(StorageError::ErrorFetchingData))
    }

    fn get_compiled_class_hash(
        &mut self,
        class_hash: &starknet_rs::utils::ClassHash,
    ) -> Result<starknet_rs::utils::CompiledClassHash, StateError> {
        // should return the compiled class hash for a sierra class hash
        let class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let casm_hash = CasmClassTable::get_compiled_class_hash(&tx, class_hash)
            .map_err(map_anyhow_to_state_err)?
            .ok_or_else(|| StateError::Storage(StorageError::ErrorFetchingData))?;

        Ok(casm_hash.0.to_be_bytes())
    }
}

// FIXME: we clearly need something more expressive than this
fn map_sqlite_to_state_err(
    _e: rusqlite::Error,
) -> starknet_rs::core::errors::state_errors::StateError {
    StateError::Storage(StorageError::ErrorFetchingData)
}

// FIXME: we clearly need something more expressive than this
fn map_anyhow_to_state_err(
    _e: anyhow::Error,
) -> starknet_rs::core::errors::state_errors::StateError {
    StateError::Storage(StorageError::ErrorFetchingData)
}
