use std::collections::HashMap;

use pathfinder_common::prelude::*;
use serde::Serialize;

use crate::dto::{SerializeForVersion, Serializer};
use crate::{dto, RpcVersion};

pub struct StateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);
pub struct PendingStateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);

pub struct StateDiff<'a>(pub &'a pathfinder_common::StateUpdate);
pub struct ContractStorageDiffItem<'a> {
    address: &'a ContractAddress,
    storage_entries: &'a HashMap<StorageAddress, StorageValue>,
}
pub struct DeployedContractItem<'a> {
    address: &'a ContractAddress,
    class_hash: &'a ClassHash,
}

impl SerializeForVersion for StateUpdate<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("block_hash", &self.0.block_hash)?;
        serializer.serialize_field("old_root", &self.0.parent_state_commitment.0)?;
        serializer.serialize_field("new_root", &self.0.state_commitment.0)?;
        serializer.serialize_field("state_diff", &StateDiff(self.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for PendingStateUpdate<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        if serializer.version < RpcVersion::V10 {
            serializer.serialize_field("old_root", &self.0.parent_state_commitment.0)?;
        }

        serializer.serialize_field("state_diff", &StateDiff(self.0))?;

        serializer.end()
    }
}

impl SerializeForVersion for StateDiff<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        struct DeclaredClass<'a> {
            sierra: &'a SierraHash,
            casm: &'a CasmHash,
        }
        struct ReplacedClass<'a> {
            address: &'a ContractAddress,
            hash: &'a ClassHash,
        }
        struct MigratedCompiledClass<'a> {
            sierra: &'a SierraHash,
            casm: &'a CasmHash,
        }
        struct Nonce<'a> {
            address: &'a ContractAddress,
            nonce: &'a ContractNonce,
        }

        impl SerializeForVersion for DeclaredClass<'_> {
            fn serialize(
                &self,
                serializer: Serializer,
            ) -> Result<crate::dto::Ok, crate::dto::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("class_hash", &self.sierra.0)?;
                serializer.serialize_field("compiled_class_hash", &self.casm.0)?;

                serializer.end()
            }
        }

        impl SerializeForVersion for ReplacedClass<'_> {
            fn serialize(
                &self,
                serializer: Serializer,
            ) -> Result<crate::dto::Ok, crate::dto::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("contract_address", &self.address)?;
                serializer.serialize_field("class_hash", &self.hash.0)?;

                serializer.end()
            }
        }

        impl SerializeForVersion for MigratedCompiledClass<'_> {
            fn serialize(
                &self,
                serializer: Serializer,
            ) -> Result<crate::dto::Ok, crate::dto::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("class_hash", &self.sierra.0)?;
                serializer.serialize_field("compiled_class_hash", &self.casm.0)?;

                serializer.end()
            }
        }

        impl SerializeForVersion for Nonce<'_> {
            fn serialize(
                &self,
                serializer: Serializer,
            ) -> Result<crate::dto::Ok, crate::dto::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("contract_address", &self.address)?;
                serializer.serialize_field("nonce", &self.nonce.0)?;

                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct()?;

        let contract_diffs =
            self.0.contract_updates.iter().filter_map(|(addr, diff)| {
                (!diff.storage.is_empty()).then_some((addr, &diff.storage))
            });
        let system_diffs = self
            .0
            .system_contract_updates
            .iter()
            .filter_map(|(addr, diff)| (!diff.storage.is_empty()).then_some((addr, &diff.storage)));
        let mut storage_diffs =
            contract_diffs
                .chain(system_diffs)
                .map(|(address, storage_entries)| ContractStorageDiffItem {
                    address,
                    storage_entries,
                });
        let diff_count = storage_diffs.clone().count();

        let mut deprecated_classes = self.0.declared_cairo_classes.iter();

        let mut declared_classes = self
            .0
            .declared_sierra_classes
            .iter()
            .map(|(sierra, casm)| DeclaredClass { sierra, casm });

        let mut deployed_contracts =
            self.0
                .contract_updates
                .iter()
                .filter_map(|(address, update)| {
                    update
                        .deployed_class()
                        .map(|class_hash| DeployedContractItem {
                            address,
                            class_hash,
                        })
                });

        let mut replaced_classes =
            self.0
                .contract_updates
                .iter()
                .filter_map(|(address, update)| {
                    update
                        .replaced_class()
                        .map(|hash| ReplacedClass { address, hash })
                });

        let mut migrated_compiled_classes = self
            .0
            .migrated_compiled_classes
            .iter()
            .map(|(sierra, casm)| MigratedCompiledClass { sierra, casm });

        let mut nonces = self
            .0
            .contract_updates
            .iter()
            .filter_map(|(address, update)| {
                update.nonce.as_ref().map(|nonce| Nonce { address, nonce })
            });

        serializer.serialize_iter("storage_diffs", diff_count, &mut storage_diffs)?;
        serializer.serialize_iter(
            "deprecated_declared_classes",
            self.0.declared_cairo_classes.len(),
            &mut deprecated_classes,
        )?;
        serializer.serialize_iter(
            "declared_classes",
            self.0.declared_sierra_classes.len(),
            &mut declared_classes,
        )?;
        serializer.serialize_iter(
            "deployed_contracts",
            deployed_contracts.clone().count(),
            &mut deployed_contracts,
        )?;
        serializer.serialize_iter(
            "replaced_classes",
            replaced_classes.clone().count(),
            &mut replaced_classes,
        )?;
        if serializer.version >= RpcVersion::V10 {
            serializer.serialize_iter(
                "migrated_compiled_classes",
                migrated_compiled_classes.clone().count(),
                &mut migrated_compiled_classes,
            )?;
        }
        serializer.serialize_iter("nonces", nonces.clone().count(), &mut nonces)?;

        serializer.end()
    }
}

impl SerializeForVersion for ContractStorageDiffItem<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        struct StorageEntry<'a> {
            key: &'a StorageAddress,
            value: &'a StorageValue,
        }

        impl SerializeForVersion for StorageEntry<'_> {
            fn serialize(
                &self,
                serializer: Serializer,
            ) -> Result<crate::dto::Ok, crate::dto::Error> {
                let mut serializer = serializer.serialize_struct()?;

                serializer.serialize_field("key", &self.key.0)?;
                serializer.serialize_field("value", &self.value.0)?;

                serializer.end()
            }
        }

        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("address", &self.address)?;
        serializer.serialize_iter(
            "storage_entries",
            self.storage_entries.len(),
            &mut self
                .storage_entries
                .iter()
                .map(|(key, value)| StorageEntry { key, value }),
        )?;

        serializer.end()
    }
}

impl SerializeForVersion for DeployedContractItem<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;

        serializer.serialize_field("address", &self.address)?;
        serializer.serialize_field("class_hash", &self.class_hash.0)?;

        serializer.end()
    }
}
