use std::collections::HashMap;

use anyhow::Context;
use cairo_felt::Felt252;
use ethers::types::U256;
use pathfinder_common::{
    CallParam, CallResultValue, ChainId, ClassHash, ContractAddress, EntryPoint, StorageAddress,
    StorageCommitment,
};
use pathfinder_merkle_tree::state_tree::{ContractsStateTree, StorageCommitmentTree};
use pathfinder_storage::{ContractCodeTable, ContractsStateTable};
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
    internal_declare::InternalDeclare, internal_deploy::InternalDeploy,
    internal_deploy_account::InternalDeployAccount,
    internal_invoke_function::InternalInvokeFunction,
};
use starknet_rs::core::errors::state_errors::StateError;
use starknet_rs::definitions::general_config::{StarknetGeneralConfig, StarknetOsConfig};
use starknet_rs::services::api::contract_class_errors::ContractClassError;
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
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

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
        starknet_rs::services::api::contract_class::EntryPointType::External,
        None,
        None,
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
    let mut state = CachedState::new(state_reader, Some(contract_class_cache));

    let chain_id = match chain_id {
        ChainId::MAINNET => starknet_rs::definitions::general_config::StarknetChainId::MainNet,
        ChainId::TESTNET => starknet_rs::definitions::general_config::StarknetChainId::TestNet,
        ChainId::TESTNET2 => starknet_rs::definitions::general_config::StarknetChainId::TestNet2,
        _ => return Err(anyhow::anyhow!("Unsupported chain id").into()),
    };

    let starknet_os_config = StarknetOsConfig::new(
        chain_id,
        starknet_rs::utils::Address(0.into()),
        gas_price.as_u64(),
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
    Deploy(InternalDeploy),
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
            Transaction::Deploy(tx) => tx.execute(state, general_config),
            Transaction::DeployAccount(tx) => tx.execute(state, general_config, true),
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
        BroadcastedTransaction::Declare(_) => todo!(),
        BroadcastedTransaction::Invoke(tx) => match tx {
            crate::v02::types::request::BroadcastedInvokeTransaction::V0(tx) => {
                let calldata = tx
                    .calldata
                    .into_iter()
                    .map(|p| Felt252::from_bytes_be(p.0.as_be_bytes()))
                    .collect();
                let signature = tx
                    .signature
                    .into_iter()
                    .map(|s| Felt252::from_bytes_be(s.0.as_be_bytes()))
                    .collect();
                let tx = InternalInvokeFunction::new(
                    Address(Felt252::from_bytes_be(
                        tx.contract_address.get().as_be_bytes(),
                    )),
                    Felt252::from_bytes_be(tx.entry_point_selector.0.as_be_bytes()),
                    tx.max_fee.0.to_low_u64_be(),
                    calldata,
                    signature,
                    Felt252::from_bytes_be(chain_id.0.as_be_bytes()),
                    tx.nonce
                        .map(|nonce| Felt252::from_bytes_be(nonce.0.as_be_bytes())),
                )?;
                Ok(Transaction::Invoke(tx))
            }
            crate::v02::types::request::BroadcastedInvokeTransaction::V1(_) => todo!(),
        },
        BroadcastedTransaction::DeployAccount(_) => todo!(),
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
    ) -> Result<starknet_rs::services::api::contract_class::ContractClass, StateError> {
        let class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let definition =
            ContractCodeTable::get_class_raw(&tx, class_hash).map_err(map_anyhow_to_state_err)?;

        match definition {
            Some(definition) => {
                let raw_contract_class: starknet_api::state::ContractClass =
                    serde_json::from_slice(&definition).map_err(|_| {
                        StateError::ContractClass(ContractClassError::NoneEntryPointType)
                    })?;
                let contract_class = raw_contract_class.into();
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

        let tree = StorageCommitmentTree::load(&tx, self.storage_commitment)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;
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
    ) -> Result<cairo_felt::Felt252, starknet_rs::core::errors::state_errors::StateError> {
        let mut db = self.storage.connection().map_err(map_anyhow_to_state_err)?;
        let tx = db.transaction().map_err(map_sqlite_to_state_err)?;

        let tree = StorageCommitmentTree::load(&tx, self.storage_commitment)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;

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

        Ok(Felt252::from_bytes_be(nonce.0.as_be_bytes()))
    }

    fn get_storage_at(
        &mut self,
        storage_entry: &starknet_rs::business_logic::state::state_cache::StorageEntry,
    ) -> Result<cairo_felt::Felt252, starknet_rs::core::errors::state_errors::StateError> {
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

        let tree = StorageCommitmentTree::load(&tx, self.storage_commitment)
            .map_err(|_| StateError::ContractAddressUnavailable(contract_address.clone()))?;

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

        let contract_state_tree = ContractsStateTree::load(&tx, contract_state_root)
            .map_err(|_| StateError::NoneStorage(storage_entry.clone()))?;

        let storage_val = contract_state_tree
            .get(storage_key)
            .map_err(|_| StateError::Storage(StorageError::ErrorFetchingData))?
            .ok_or_else(|| StateError::NoneStorage(storage_entry.clone()))?;

        Ok(Felt252::from_bytes_be(storage_val.0.as_be_bytes()))
    }

    fn count_actual_storage_changes(&mut self) -> (usize, usize) {
        // read-only storage
        (0, 0)
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
