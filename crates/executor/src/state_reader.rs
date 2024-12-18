use blockifier::execution::contract_class::RunnableCompiledClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateReader;
use pathfinder_common::{BlockNumber, ClassHash, StorageAddress, StorageValue};
use pathfinder_crypto::Felt;
use starknet_api::StarknetApiError;
use starknet_types_core::felt::Felt as CoreFelt;

use super::felt::{IntoFelt, IntoStarkFelt};
use crate::lru_cache::GLOBAL_CACHE;

pub(super) struct PathfinderStateReader<'tx> {
    transaction: &'tx pathfinder_storage::Transaction<'tx>,
    pub block_number: Option<BlockNumber>,
    // Classes in pending state have already been downloaded and added to the database.
    // This flag makes it possible to find these classes -- essentially makes the state
    // reader look up classes which are not declared at a canonical block yet.
    ignore_block_number_for_classes: bool,
}

impl<'tx> PathfinderStateReader<'tx> {
    pub fn new(
        transaction: &'tx pathfinder_storage::Transaction<'tx>,
        block_number: Option<BlockNumber>,
        ignore_block_number_for_classes: bool,
    ) -> Self {
        Self {
            transaction,
            block_number,
            ignore_block_number_for_classes,
        }
    }

    fn state_block_id(&self) -> Option<pathfinder_storage::BlockId> {
        self.block_number.map(Into::into)
    }

    fn non_cached_compiled_contract_class(
        &self,
        pathfinder_class_hash: ClassHash,
        class_hash: &starknet_api::core::ClassHash,
    ) -> Result<(Option<BlockNumber>, RunnableCompiledClass), StateError> {
        tracing::trace!("Getting class");

        let block_id = self.state_block_id().ok_or_else(|| {
            StateError::UndeclaredClassHash(starknet_api::core::ClassHash(
                pathfinder_class_hash.0.into_starkfelt(),
            ))
        })?;

        let block_number_and_casm_definition = if self.ignore_block_number_for_classes {
            self.transaction
                .casm_definition_with_block_number(pathfinder_class_hash)
        } else {
            self.transaction
                .casm_definition_at_with_block_number(block_id, pathfinder_class_hash)
        };

        if let Some((definition_block_number, casm_definition)) =
            block_number_and_casm_definition.map_err(map_anyhow_to_state_err)?
        {
            // This is a Sierra class.
            #[cfg(feature = "cairo-native")]
            let runnable_class =
                self.sierra_class_as_native(pathfinder_class_hash, casm_definition)?;
            #[cfg(not(feature = "cairo-native"))]
            let runnable_class = self.sierra_class_as_casm(casm_definition)?;

            return Ok((definition_block_number, runnable_class));
        }

        let definition = if self.ignore_block_number_for_classes {
            self.transaction
                .class_definition_with_block_number(pathfinder_class_hash)
        } else {
            self.transaction
                .class_definition_at_with_block_number(block_id, pathfinder_class_hash)
                .map(|option| {
                    option.map(|(block_number, definition)| (Some(block_number), definition))
                })
        };

        if let Some((definition_block_number, definition)) =
            definition.map_err(map_anyhow_to_state_err)?
        {
            // This is a Cairo 0 class.
            let definition = String::from_utf8(definition).map_err(|error| {
                StateError::StateReadError(format!(
                    "Class definition is not valid UTF-8: {}",
                    error
                ))
            })?;

            let class =
                blockifier::execution::contract_class::CompiledClassV0::try_from_json_string(
                    &definition,
                )
                .map_err(StateError::ProgramError)?;

            return Ok((definition_block_number, RunnableCompiledClass::V0(class)));
        }

        tracing::trace!("Class definition not found");

        Err(StateError::UndeclaredClassHash(*class_hash))
    }

    #[cfg(feature = "cairo-native")]
    fn sierra_class_as_native(
        &self,
        class_hash: ClassHash,
        casm_definition: Vec<u8>,
    ) -> Result<RunnableCompiledClass, StateError> {
        // FIXME: unwraps
        let sierra_definition = self
            .transaction
            .class_definition(class_hash)
            .map_err(map_anyhow_to_state_err)?
            .expect("Sierra class should be present if we have CASM");
        let mut sierra_definition: serde_json::Value =
            serde_json::from_slice(&sierra_definition)
                .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;
        sierra_definition["abi"] = serde_json::from_str(sierra_definition["abi"].as_str().unwrap())
            .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;

        let sierra_class: cairo_lang_starknet_classes::contract_class::ContractClass =
            serde_json::from_value(sierra_definition)
                .map_err(|e| StateError::ProgramError(ProgramError::Parse(e)))?;
        let sierra_program = sierra_class.extract_sierra_program().map_err(|e| {
            StateError::StateReadError(format!(
                "Error parsing Sierra
                program: {}",
                e
            ))
        })?;

        use blockifier::execution::native::contract_class::NativeCompiledClassV1;
        use cairo_native::executor::AotContractExecutor;
        use cairo_vm::types::errors::program_errors::ProgramError;

        let contract_executor = AotContractExecutor::new(
            &sierra_program,
            &sierra_class.entry_points_by_type,
            Default::default(),
        )
        .unwrap();

        let casm_definition = String::from_utf8(casm_definition).map_err(|error| {
            StateError::StateReadError(format!("Class definition is not valid UTF-8: {}", error))
        })?;

        let casm_class =
            blockifier::execution::contract_class::CompiledClassV1::try_from_json_string(
                &casm_definition,
            )
            .map_err(StateError::ProgramError)?;

        let runnable_class = RunnableCompiledClass::V1Native(NativeCompiledClassV1::new(
            contract_executor,
            casm_class,
        ));

        Ok(runnable_class)
    }

    #[cfg(not(feature = "cairo-native"))]
    fn sierra_class_as_casm(
        &self,
        casm_definition: Vec<u8>,
    ) -> Result<RunnableCompiledClass, StateError> {
        let casm_definition = String::from_utf8(casm_definition).map_err(|error| {
            StateError::StateReadError(format!("Class definition is not valid UTF-8: {}", error))
        })?;

        let casm_class =
            blockifier::execution::contract_class::CompiledClassV1::try_from_json_string(
                &casm_definition,
            )
            .map_err(StateError::ProgramError)?;

        Ok(RunnableCompiledClass::V1(casm_class))
    }
}

impl StateReader for PathfinderStateReader<'_> {
    fn get_storage_at(
        &self,
        contract_address: starknet_api::core::ContractAddress,
        storage_key: starknet_api::state::StorageKey,
    ) -> blockifier::state::state_api::StateResult<CoreFelt> {
        let storage_key =
            StorageAddress::new(storage_key.0.key().into_felt()).ok_or_else(|| {
                StateError::StarknetApiError(StarknetApiError::OutOfRange {
                    string: "Storage key out of range".to_owned(),
                })
            })?;

        let pathfinder_contract_address =
            pathfinder_common::ContractAddress::new_or_panic(contract_address.0.key().into_felt());

        let _span =
            tracing::trace_span!("get_storage_at", contract_address=%pathfinder_contract_address, %storage_key)
                .entered();

        tracing::trace!("Getting storage value");

        let Some(block_id) = self.state_block_id() else {
            return Ok(Felt::ZERO.into_starkfelt());
        };

        let storage_val = self
            .transaction
            .storage_value(block_id, pathfinder_contract_address, storage_key)
            .map_err(map_anyhow_to_state_err)?
            .unwrap_or(StorageValue(Felt::ZERO));

        tracing::trace!(storage_value=%storage_val, "Got storage value");

        Ok(storage_val.0.into_starkfelt())
    }

    fn get_nonce_at(
        &self,
        contract_address: starknet_api::core::ContractAddress,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::Nonce> {
        let pathfinder_contract_address =
            pathfinder_common::ContractAddress::new_or_panic(contract_address.0.key().into_felt());

        let _span =
            tracing::trace_span!("get_nonce_at", contract_address=%pathfinder_contract_address)
                .entered();

        tracing::trace!("Getting nonce for contract");

        let Some(block_id) = self.state_block_id() else {
            return Ok(starknet_api::core::Nonce(
                pathfinder_common::ContractNonce::ZERO.0.into_starkfelt(),
            ));
        };

        let nonce = self
            .transaction
            .contract_nonce(pathfinder_contract_address, block_id)
            .map_err(map_anyhow_to_state_err)?
            .unwrap_or(pathfinder_common::ContractNonce::ZERO);

        Ok(starknet_api::core::Nonce(nonce.0.into_starkfelt()))
    }

    fn get_class_hash_at(
        &self,
        contract_address: starknet_api::core::ContractAddress,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::ClassHash> {
        let pathfinder_contract_address =
            pathfinder_common::ContractAddress::new_or_panic(contract_address.0.key().into_felt());

        let _span = tracing::trace_span!("get_class_hash_at", contract_address=%pathfinder_contract_address).entered();

        tracing::trace!("Getting class hash at contract");

        let Some(block_id) = self.state_block_id() else {
            return Ok(starknet_api::core::ClassHash(
                ClassHash::ZERO.0.into_starkfelt(),
            ));
        };

        let class_hash = self
            .transaction
            .contract_class_hash(block_id, pathfinder_contract_address)
            .map_err(map_anyhow_to_state_err)?;

        let Some(class_hash) = class_hash else {
            return Ok(starknet_api::core::ClassHash(
                ClassHash::ZERO.0.into_starkfelt(),
            ));
        };

        Ok(starknet_api::core::ClassHash(class_hash.0.into_starkfelt()))
    }

    fn get_compiled_class(
        &self,
        class_hash: starknet_api::core::ClassHash,
    ) -> blockifier::state::state_api::StateResult<RunnableCompiledClass> {
        let pathfinder_class_hash = ClassHash(class_hash.0.into_felt());

        let _span =
            tracing::trace_span!("get_compiled_contract_class", class_hash=%pathfinder_class_hash)
                .entered();

        if let Some(entry) = GLOBAL_CACHE.get(&class_hash) {
            if let Some(reader_block_number) = self.block_number {
                if entry.height <= reader_block_number {
                    tracing::trace!("Global class cache hit");
                    return Ok(entry.definition);
                }
            }
        }

        let (definition_block_number, contract_class) =
            self.non_cached_compiled_contract_class(pathfinder_class_hash, &class_hash)?;

        if let Some(block_number) = definition_block_number {
            GLOBAL_CACHE.set(class_hash, contract_class.clone(), block_number);
        }

        Ok(contract_class)
    }

    fn get_compiled_class_hash(
        &self,
        class_hash: starknet_api::core::ClassHash,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::CompiledClassHash> {
        let class_hash = ClassHash(class_hash.0.into_felt());

        tracing::trace!(%class_hash, "Getting compiled class hash");

        let block_id = self.state_block_id().ok_or_else(|| {
            StateError::UndeclaredClassHash(starknet_api::core::ClassHash(
                class_hash.0.into_starkfelt(),
            ))
        })?;

        let casm_hash = if self.ignore_block_number_for_classes {
            self.transaction.casm_hash(class_hash)
        } else {
            self.transaction.casm_hash_at(block_id, class_hash)
        };

        let casm_hash = casm_hash.map_err(map_anyhow_to_state_err)?.ok_or_else(|| {
            StateError::StateReadError("Error getting compiled class hash".to_owned())
        })?;

        Ok(starknet_api::core::CompiledClassHash(
            casm_hash.0.into_starkfelt(),
        ))
    }
}

fn map_anyhow_to_state_err(error: anyhow::Error) -> StateError {
    tracing::error!(%error, "Internal error in execution state reader");
    StateError::StateReadError(error.to_string())
}
