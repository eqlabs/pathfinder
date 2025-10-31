use blockifier::execution::contract_class::RunnableCompiledClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateReader;
use pathfinder_common::{BlockNumber, ClassHash, StorageAddress, StorageValue};
use pathfinder_crypto::Felt;
use starknet_api::contract_class::SierraVersion;
use starknet_api::StarknetApiError;
use starknet_types_core::felt::Felt as CoreFelt;

use super::felt::{IntoFelt, IntoStarkFelt};
use crate::lru_cache::GLOBAL_CACHE;
pub(crate) use crate::state_reader::storage_adapter::StorageAdapter;

#[cfg(feature = "cairo-native")]
mod native;
#[cfg(feature = "cairo-native")]
pub use native::NativeClassCache;
mod storage_adapter;

pub use storage_adapter::concurrent::ConcurrentStorageAdapter;
pub(crate) use storage_adapter::rc::RcStorageAdapter;

#[cfg(not(feature = "cairo-native"))]
#[derive(Clone)]
pub struct NativeClassCache;

#[cfg(not(feature = "cairo-native"))]
impl NativeClassCache {
    pub fn spawn(_cache_size: std::num::NonZeroUsize) -> Self {
        Self {}
    }
}

#[derive(Clone)]
pub struct PathfinderStateReader<S> {
    storage_adapter: S,
    pub block_number: Option<BlockNumber>,
    // Classes in pending state have already been downloaded and added to the database.
    // This flag makes it possible to find these classes -- essentially makes the state
    // reader look up classes which are not declared at a canonical block yet.
    ignore_block_number_for_classes: bool,
    #[allow(unused)]
    native_class_cache: Option<NativeClassCache>,
}

impl<S: StorageAdapter> PathfinderStateReader<S> {
    pub fn new(
        storage_adapter: S,
        block_number: Option<BlockNumber>,
        ignore_block_number_for_classes: bool,
        native_class_cache: Option<NativeClassCache>,
    ) -> Self {
        Self {
            storage_adapter,
            block_number,
            ignore_block_number_for_classes,
            native_class_cache,
        }
    }

    fn state_block_id(&self) -> Option<pathfinder_common::BlockId> {
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

        let (definition_block_number, class_definition, casm_definition) =
            if self.ignore_block_number_for_classes {
                let casm_definition = self
                    .storage_adapter
                    .casm_definition(pathfinder_class_hash)?;
                let (definition_block_number, class_definition) = self
                    .storage_adapter
                    .class_definition_with_block_number(pathfinder_class_hash)?
                    .ok_or_else(|| {
                        tracing::trace!("Class definition not found");
                        StateError::UndeclaredClassHash(*class_hash)
                    })?;
                (definition_block_number, class_definition, casm_definition)
            } else {
                let casm_definition = self
                    .storage_adapter
                    .casm_definition_at(block_id, pathfinder_class_hash)?;
                let (definition_block_number, class_definition) = self
                    .storage_adapter
                    .class_definition_at_with_block_number(block_id, pathfinder_class_hash)?
                    .ok_or_else(|| {
                        tracing::trace!("Class definition not found");
                        StateError::UndeclaredClassHash(*class_hash)
                    })?;
                (
                    Some(definition_block_number),
                    class_definition,
                    casm_definition,
                )
            };

        match casm_definition {
            Some(casm_definition) => {
                // There's a CASM definition in storage, so this is a Sierra class. Extract
                // class version from program.
                let sierra_version = self.sierra_version_from_class(&class_definition)?;

                #[cfg(feature = "cairo-native")]
                let runnable_class = if sierra_version >= SierraVersion::new(1, 7, 0) {
                    if let Some(native_class_cache) = &self.native_class_cache {
                        match native_class_cache.get(
                            pathfinder_class_hash,
                            sierra_version.clone(),
                            class_definition,
                            casm_definition.clone(),
                        ) {
                            Some(native_class) => RunnableCompiledClass::V1Native(native_class),
                            None => {
                                let runnable_class =
                                    sierra_class_as_casm(sierra_version, casm_definition)?;
                                // FIXME: this is a hack to avoid caching the CASM
                                // class in the global cache until Native
                                // compilation is finished
                                return Ok((None, runnable_class));
                            }
                        }
                    } else {
                        // Native execution is disabled.
                        sierra_class_as_casm(sierra_version, casm_definition)?
                    }
                } else {
                    // Pre-1.7 Sierra classes are not natively compiled.
                    sierra_class_as_casm(sierra_version, casm_definition)?
                };

                #[cfg(not(feature = "cairo-native"))]
                let runnable_class = sierra_class_as_casm(sierra_version, casm_definition)?;

                Ok((definition_block_number, runnable_class))
            }
            None => {
                // No CASM definition means this is a legacy Cairo 0 class.
                let class_definition = String::from_utf8(class_definition).map_err(|error| {
                    StateError::StateReadError(format!(
                        "Class definition is not valid UTF-8: {error}"
                    ))
                })?;

                let class =
                    blockifier::execution::contract_class::CompiledClassV0::try_from_json_string(
                        &class_definition,
                    )
                    .map_err(StateError::ProgramError)?;

                Ok((definition_block_number, RunnableCompiledClass::V0(class)))
            }
        }
    }

    fn sierra_version_from_class(
        &self,
        class_definition: &[u8],
    ) -> Result<SierraVersion, StateError> {
        use cairo_vm::types::errors::program_errors::ProgramError;

        let sierra_class: pathfinder_common::class_definition::Sierra<'_> =
            serde_json::from_slice(class_definition)
                .map_err(|error| StateError::ProgramError(ProgramError::Parse(error)))?;
        SierraVersion::extract_from_program(&sierra_class.sierra_program).map_err(Into::into)
    }
}

fn sierra_class_as_casm(
    sierra_version: SierraVersion,
    casm_definition: Vec<u8>,
) -> Result<RunnableCompiledClass, StateError> {
    let casm_definition = String::from_utf8(casm_definition).map_err(|error| {
        StateError::StateReadError(format!("CASM definition is not valid UTF-8: {error}"))
    })?;
    let casm_class = blockifier::execution::contract_class::CompiledClassV1::try_from_json_string(
        &casm_definition,
        sierra_version,
    )
    .map_err(StateError::ProgramError)?;

    Ok(RunnableCompiledClass::V1(casm_class))
}

impl<S: StorageAdapter> StateReader for PathfinderStateReader<S> {
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
            .storage_adapter
            .storage_value(block_id, pathfinder_contract_address, storage_key)?
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
            .storage_adapter
            .contract_nonce(pathfinder_contract_address, block_id)?
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
            .storage_adapter
            .contract_class_hash(block_id, pathfinder_contract_address)?;

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
            self.storage_adapter.casm_hash(class_hash)
        } else {
            self.storage_adapter.casm_hash_at(block_id, class_hash)
        };

        let casm_hash = casm_hash?.ok_or_else(|| {
            StateError::StateReadError("Error getting compiled class hash".to_owned())
        })?;

        Ok(starknet_api::core::CompiledClassHash(
            casm_hash.0.into_starkfelt(),
        ))
    }
}
