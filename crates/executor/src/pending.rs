use std::sync::Arc;

use blockifier::execution::contract_class::RunnableCompiledClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateReader;
use pathfinder_common::{StateUpdate, StorageAddress};
use starknet_api::core::ContractAddress;
use starknet_api::state::StorageKey;
use starknet_api::StarknetApiError;

use super::felt::{IntoFelt, IntoStarkFelt};

#[derive(Clone)]
pub struct PendingStateReader<S: StateReader + Clone> {
    state: S,
    pending_update: Option<Arc<StateUpdate>>,
}

impl<S: StateReader + Clone> PendingStateReader<S> {
    pub(super) fn new(state: S, pending_update: Option<Arc<StateUpdate>>) -> Self {
        Self {
            state,
            pending_update,
        }
    }
}

impl<S: StateReader + Clone> StateReader for PendingStateReader<S> {
    fn get_storage_at(
        &self,
        contract_address: ContractAddress,
        key: StorageKey,
    ) -> blockifier::state::state_api::StateResult<starknet_types_core::felt::Felt> {
        let storage_key = StorageAddress::new(key.0.key().into_felt()).ok_or_else(|| {
            StateError::StarknetApiError(StarknetApiError::OutOfRange {
                string: "Storage key out of range".to_owned(),
            })
        })?;

        let pathfinder_contract_address =
            pathfinder_common::ContractAddress::new_or_panic(contract_address.0.key().into_felt());

        self.pending_update
            .as_ref()
            .and_then(|pending_update| {
                pending_update
                    .storage_value(pathfinder_contract_address, storage_key)
                    .map(|value| Ok(value.0.into_starkfelt()))
            })
            .unwrap_or_else(|| self.state.get_storage_at(contract_address, key))
    }

    fn get_nonce_at(
        &self,
        contract_address: ContractAddress,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::Nonce> {
        let pathfinder_contract_address =
            pathfinder_common::ContractAddress::new_or_panic(contract_address.0.key().into_felt());

        self.pending_update
            .as_ref()
            .and_then(|pending_update| {
                pending_update
                    .contract_nonce(pathfinder_contract_address)
                    .map(|nonce| Ok(starknet_api::core::Nonce(nonce.0.into_starkfelt())))
            })
            .unwrap_or_else(|| self.state.get_nonce_at(contract_address))
    }

    fn get_class_hash_at(
        &self,
        contract_address: ContractAddress,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::ClassHash> {
        let pathfinder_contract_address =
            pathfinder_common::ContractAddress::new_or_panic(contract_address.0.key().into_felt());

        self.pending_update
            .as_ref()
            .and_then(|pending_update| {
                pending_update
                    .contract_class(pathfinder_contract_address)
                    .map(|class_hash| {
                        Ok(starknet_api::core::ClassHash(class_hash.0.into_starkfelt()))
                    })
            })
            .unwrap_or_else(|| self.state.get_class_hash_at(contract_address))
    }

    fn get_compiled_class(
        &self,
        class_hash: starknet_api::core::ClassHash,
    ) -> blockifier::state::state_api::StateResult<RunnableCompiledClass> {
        self.state.get_compiled_class(class_hash)
    }

    fn get_compiled_class_hash(
        &self,
        class_hash: starknet_api::core::ClassHash,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::CompiledClassHash> {
        self.state.get_compiled_class_hash(class_hash)
    }

    fn get_compiled_class_hash_v2(
        &self,
        class_hash: starknet_api::core::ClassHash,
        compiled_class: &RunnableCompiledClass,
    ) -> blockifier::state::state_api::StateResult<starknet_api::core::CompiledClassHash> {
        self.state
            .get_compiled_class_hash_v2(class_hash, compiled_class)
    }
}

#[cfg(test)]
mod tests {
    use blockifier::execution::contract_class::RunnableCompiledClass;
    use blockifier::state::state_api::StateReader;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::StateUpdate;
    use starknet_types_core::felt::Felt as CoreFelt;

    use super::PendingStateReader;

    #[derive(Clone)]
    struct DummyStateReader {}

    impl StateReader for DummyStateReader {
        fn get_storage_at(
            &self,
            _contract_address: starknet_api::core::ContractAddress,
            _key: starknet_api::state::StorageKey,
        ) -> blockifier::state::state_api::StateResult<CoreFelt> {
            Ok(CoreFelt::from(u32::MAX))
        }

        fn get_nonce_at(
            &self,
            _contract_address: starknet_api::core::ContractAddress,
        ) -> blockifier::state::state_api::StateResult<starknet_api::core::Nonce> {
            Ok(starknet_api::core::Nonce(CoreFelt::from(u32::MAX)))
        }

        fn get_class_hash_at(
            &self,
            _contract_address: starknet_api::core::ContractAddress,
        ) -> blockifier::state::state_api::StateResult<starknet_api::core::ClassHash> {
            Ok(starknet_api::core::ClassHash(CoreFelt::from(u32::MAX)))
        }

        fn get_compiled_class(
            &self,
            _class_hash: starknet_api::core::ClassHash,
        ) -> blockifier::state::state_api::StateResult<RunnableCompiledClass> {
            unimplemented!()
        }

        fn get_compiled_class_hash(
            &self,
            _class_hash: starknet_api::core::ClassHash,
        ) -> blockifier::state::state_api::StateResult<starknet_api::core::CompiledClassHash>
        {
            Ok(starknet_api::core::CompiledClassHash(CoreFelt::from(
                u32::MAX,
            )))
        }
    }

    #[test]
    fn test_pending_nonce() {
        let state_update = StateUpdate::default()
            .with_contract_nonce(contract_address!("0x2"), contract_nonce!("0x3"));

        let uut = PendingStateReader::new(DummyStateReader {}, Some(state_update.into()));

        // Nonce set in pending.
        let nonce = uut
            .get_nonce_at(starknet_api::core::ContractAddress(
                starknet_api::core::PatriciaKey::try_from(CoreFelt::from(2u8)).unwrap(),
            ))
            .unwrap();
        assert_eq!(nonce, starknet_api::core::Nonce(CoreFelt::from(3u8),));

        // Nonce not set in pending.
        let nonce = uut
            .get_nonce_at(starknet_api::core::ContractAddress(
                starknet_api::core::PatriciaKey::try_from(CoreFelt::from(1u8)).unwrap(),
            ))
            .unwrap();
        assert_eq!(nonce, starknet_api::core::Nonce(CoreFelt::from(u32::MAX),));
    }

    #[test]
    fn test_pending_storage_update() {
        let state_update = StateUpdate::default().with_storage_update(
            contract_address!("0x2"),
            storage_address!("0x3"),
            storage_value!("0x4"),
        );

        let uut = PendingStateReader::new(DummyStateReader {}, Some(state_update.into()));

        // Storage set in pending.
        let storage = uut
            .get_storage_at(
                starknet_api::core::ContractAddress(
                    starknet_api::core::PatriciaKey::try_from(CoreFelt::from(2u8)).unwrap(),
                ),
                starknet_api::state::StorageKey(
                    starknet_api::core::PatriciaKey::try_from(CoreFelt::from(3u8)).unwrap(),
                ),
            )
            .unwrap();
        assert_eq!(storage, CoreFelt::from(4u8));

        // Storage not set in pending.
        let storage = uut
            .get_storage_at(
                starknet_api::core::ContractAddress(
                    starknet_api::core::PatriciaKey::try_from(CoreFelt::from(1u8)).unwrap(),
                ),
                starknet_api::state::StorageKey(
                    starknet_api::core::PatriciaKey::try_from(CoreFelt::from(3u8)).unwrap(),
                ),
            )
            .unwrap();
        assert_eq!(storage, CoreFelt::from(u32::MAX));
    }

    #[test]
    fn test_pending_class_hash_at() {
        let state_update = StateUpdate::default()
            .with_deployed_contract(contract_address!("0x2"), class_hash!("0x3"));

        let uut = PendingStateReader::new(DummyStateReader {}, Some(state_update.into()));

        // Contract deployed in pending
        let class_hash = uut
            .get_class_hash_at(starknet_api::core::ContractAddress(
                starknet_api::core::PatriciaKey::try_from(CoreFelt::from(2u8)).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            class_hash,
            starknet_api::core::ClassHash(CoreFelt::from(3u8))
        );

        // Contract not deployed in pending
        let class_hash = uut
            .get_class_hash_at(starknet_api::core::ContractAddress(
                starknet_api::core::PatriciaKey::try_from(CoreFelt::from(1u8)).unwrap(),
            ))
            .unwrap();
        assert_eq!(
            class_hash,
            starknet_api::core::ClassHash(CoreFelt::from(u32::MAX))
        );
    }
}
