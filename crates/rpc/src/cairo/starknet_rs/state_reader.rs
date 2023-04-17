use std::str::FromStr;

use pathfinder_common::{BlockNumber, ClassHash, ContractNonce, StorageAddress, StorageValue};
use stark_hash::Felt;
use starknet_in_rust::core::errors::state_errors::StateError;

use starknet_in_rust::services::api::contract_classes::compiled_class::CompiledClass;
use starknet_in_rust::services::api::contract_classes::deprecated_contract_class::ContractClass;
use starknet_in_rust::state::state_api::StateReader;
use starknet_in_rust::{felt::Felt252, CasmContractClass};

use crate::cairo::starknet_rs::felt::IntoFelt252;

pub struct PathfinderStateReader<'conn> {
    transaction: pathfinder_storage::Transaction<'conn>,
    block_number: Option<BlockNumber>,
    // Classes in pending state have already been downloaded and added to the database.
    // This flag makes it possible to find these classes -- essentially makes the state
    // reader look up classes which are not declared at a canonical block yet.
    ignore_block_number_for_classes: bool,
}

impl<'conn> PathfinderStateReader<'conn> {
    pub fn new(
        connection: &'conn mut pathfinder_storage::Connection,
        block_number: Option<BlockNumber>,
        ignore_block_number_for_classes: bool,
    ) -> anyhow::Result<Self> {
        let transaction = connection.transaction()?;

        Ok(Self {
            transaction,
            block_number,
            ignore_block_number_for_classes,
        })
    }

    fn state_block_id(&self) -> Option<pathfinder_storage::BlockId> {
        self.block_number.map(Into::into)
    }
}

impl StateReader for PathfinderStateReader<'_> {
    fn get_class_hash_at(
        &self,
        contract_address: &starknet_in_rust::utils::Address,
    ) -> Result<starknet_in_rust::utils::ClassHash, StateError> {
        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );

        let _span = tracing::debug_span!("get_class_hash_at", contract_address=%pathfinder_contract_address).entered();

        tracing::trace!("Getting class hash at contract");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?;

        let class_hash = self
            .transaction
            .contract_class_hash(block_id, pathfinder_contract_address)
            .map_err(|error| {
                tracing::error!(%error, "Failed to fetch contract class hash");
                StateError::CustomError(format!(
                    "Failed to fetch contract class hash for contract {}",
                    pathfinder_contract_address
                ))
            })?
            .ok_or_else(|| StateError::NoneClassHash(contract_address.clone()))?;

        Ok(class_hash.0.to_be_bytes())
    }

    fn get_nonce_at(
        &self,
        contract_address: &starknet_in_rust::utils::Address,
    ) -> Result<Felt252, starknet_in_rust::core::errors::state_errors::StateError> {
        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );

        let _span =
            tracing::debug_span!("get_nonce_at", contract_address=%pathfinder_contract_address)
                .entered();

        tracing::trace!("Getting nonce for contract");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneNonce(contract_address.clone()))?;

        let nonce = self
            .transaction
            .contract_nonce(pathfinder_contract_address, block_id)
            .map_err(|error| {
                tracing::error!(%error, "Failed to fetch contract nonce");
                StateError::CustomError(format!("Failed to fetch contract nonce: {}", error))
            })?
            .unwrap_or(ContractNonce(Felt::ZERO));

        Ok(nonce.0.into_felt252())
    }

    fn get_storage_at(
        &self,
        storage_entry: &starknet_in_rust::state::state_cache::StorageEntry,
    ) -> Result<Felt252, starknet_in_rust::core::errors::state_errors::StateError> {
        let (contract_address, storage_key) = storage_entry;
        let storage_key =
            StorageAddress::new(Felt::from_be_slice(storage_key).map_err(|_| {
                StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
            })?)
            .ok_or_else(|| {
                StateError::ContractAddressOutOfRangeAddress(contract_address.clone())
            })?;

        let pathfinder_contract_address = pathfinder_common::ContractAddress::new_or_panic(
            Felt::from_be_slice(&contract_address.0.to_bytes_be())
                .expect("Overflow in contract address"),
        );

        let _span =
            tracing::debug_span!("get_storage_at", contract_address=%pathfinder_contract_address, %storage_key)
                .entered();

        tracing::trace!("Getting storage value");

        let Some(block_id) = self.state_block_id() else {
            return Ok(Felt::ZERO.into_felt252());
        };

        let storage_val = self
            .transaction
            .storage_value(block_id, pathfinder_contract_address, storage_key)
            .map_err(|error| {
                tracing::error!(%error, %storage_key, "Failed to fetch storage value");
                StateError::CustomError(format!("Failed to fetch storage value: {}", error))
            })?
            .unwrap_or(StorageValue(Felt::ZERO));

        Ok(storage_val.0.into_felt252())
    }

    fn get_contract_class(
        &self,
        class_hash: &starknet_in_rust::utils::ClassHash,
    ) -> Result<CompiledClass, StateError> {
        let pathfinder_class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let _span =
            tracing::debug_span!("get_compiled_class", class_hash=%pathfinder_class_hash).entered();

        tracing::trace!("Getting class");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneCompiledHash(*class_hash))?;

        let casm_definition = if self.ignore_block_number_for_classes {
            self.transaction.casm_definition(pathfinder_class_hash)
        } else {
            self.transaction
                .casm_definition_at(block_id, pathfinder_class_hash)
        };

        if let Some(casm_definition) = casm_definition.map_err(map_anyhow_to_state_err)? {
            let casm_class: CasmContractClass =
                serde_json::from_slice(&casm_definition).map_err(|error| {
                    tracing::error!(%error, "Failed to parse CASM class definition");
                    StateError::CustomError(format!(
                        "Failed to parse CASM class definition: {}",
                        error
                    ))
                })?;
            return Ok(CompiledClass::Casm(casm_class.into()));
        }

        let definition = if self.ignore_block_number_for_classes {
            self.transaction.class_definition(pathfinder_class_hash)
        } else {
            self.transaction
                .class_definition_at(block_id, pathfinder_class_hash)
        };

        if let Some(definition) = definition.map_err(map_anyhow_to_state_err)? {
            let definition = String::from_utf8(definition).map_err(|error| {
                tracing::error!(%error, "Failed to parse Cairo class definition to UTF-8 string");
                StateError::CustomError(format!(
                    "Failed to parse Cairo class definition as UTF-8: {}",
                    error
                ))
            })?;

            let contract_class = ContractClass::from_str(definition.as_str()).map_err(|error| {
                tracing::error!(%error, "Failed to parse class definition");
                StateError::CustomError(format!(
                    "Failed to parse Cairo class definition: {}",
                    error
                ))
            })?;

            return Ok(CompiledClass::Deprecated(contract_class.into()));
        }

        tracing::trace!(%pathfinder_class_hash, "Class definition not found");
        Err(StateError::NoneCompiledHash(*class_hash))
    }

    fn get_compiled_class_hash(
        &self,
        class_hash: &starknet_in_rust::utils::ClassHash,
    ) -> Result<starknet_in_rust::utils::CompiledClassHash, StateError> {
        // should return the compiled class hash for a sierra class hash
        let pathfinder_class_hash =
            ClassHash(Felt::from_be_slice(class_hash).expect("Overflow in class hash"));

        let _span =
            tracing::debug_span!("get_compiled_class_hash", %pathfinder_class_hash).entered();

        tracing::trace!("Getting compiled class hash");

        let block_id = self
            .state_block_id()
            .ok_or_else(|| StateError::NoneCompiledHash(*class_hash))?;

        let casm_hash = if self.ignore_block_number_for_classes {
            self.transaction.casm_hash(pathfinder_class_hash)
        } else {
            self.transaction
                .casm_hash_at(block_id, pathfinder_class_hash)
        };

        let casm_hash = casm_hash
            .map_err(map_anyhow_to_state_err)?
            .ok_or(StateError::NoneCompiledHash(*class_hash))?;

        Ok(casm_hash.0.to_be_bytes())
    }
}

fn map_anyhow_to_state_err(
    error: anyhow::Error,
) -> starknet_in_rust::core::errors::state_errors::StateError {
    tracing::error!(?error, "Internal error in state reader");
    StateError::CustomError(format!("Internal error in state reader: {}", error))
}
