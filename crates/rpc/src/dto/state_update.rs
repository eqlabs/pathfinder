use super::serialize::SerializeForVersion;
use crate::dto::*;
use std::collections::HashMap;

pub struct PendingStateUpdate<'a>(pub &'a pathfinder_common::StateUpdate);

pub struct StateDiff<'a>(pub &'a pathfinder_common::StateUpdate);

pub struct ContractStorageDiffItem<'a> {
    address: &'a pathfinder_common::ContractAddress,
    entries: &'a HashMap<pathfinder_common::StorageAddress, pathfinder_common::StorageValue>,
}

pub struct DeployedContractItem<'a> {
    address: &'a pathfinder_common::ContractAddress,
    class_hash: &'a pathfinder_common::ClassHash,
}

impl SerializeForVersion for PendingStateUpdate<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("old_root", &Felt(&self.0.parent_state_commitment.0))?;
        serializer.serialize_field("state_diff", &StateDiff(self.0))?;
        serializer.end()
    }
}

impl SerializeForVersion for StateDiff<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        use pathfinder_common::state_update::ContractClassUpdate;

        struct DeclaredClass<'a> {
            class_hash: &'a pathfinder_common::SierraHash,
            casm_hash: &'a pathfinder_common::CasmHash,
        }

        struct ReplacedClass<'a> {
            address: &'a pathfinder_common::ContractAddress,
            class: &'a pathfinder_common::ClassHash,
        }

        struct NonceUpdate<'a> {
            address: &'a pathfinder_common::ContractAddress,
            nonce: &'a pathfinder_common::ContractNonce,
        }

        impl SerializeForVersion for DeclaredClass<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("class_hash", &Felt(&self.class_hash.0))?;
                serializer.serialize_field("compiled_class_hash", &Felt(&self.casm_hash.0))?;
                serializer.end()
            }
        }

        impl SerializeForVersion for ReplacedClass<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("class_hash", &Felt(&self.class.0))?;
                serializer.serialize_field("contract_address", &Address(self.address))?;
                serializer.end()
            }
        }

        impl SerializeForVersion for NonceUpdate<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("nonce", &Felt(&self.nonce.0))?;
                serializer.serialize_field("contract_address", &Address(self.address))?;
                serializer.end()
            }
        }

        let mut s = serializer.serialize_struct()?;

        let contract_diffs = self
            .0
            .contract_updates
            .iter()
            .map(|(addr, updates)| (addr, &updates.storage));
        let system_diffs = self
            .0
            .system_contract_updates
            .iter()
            .map(|(addr, updates)| (addr, &updates.storage));
        let mut storage_diffs =
            contract_diffs
                .chain(system_diffs)
                .filter_map(|(address, entries)| {
                    (!entries.is_empty()).then_some(ContractStorageDiffItem { address, entries })
                });
        let count = storage_diffs.clone().count();
        s.serialize_iter("storage_diffs", count, &mut storage_diffs)?;

        s.serialize_iter(
            "deprecated_declared_classes",
            self.0.declared_cairo_classes.len(),
            &mut self.0.declared_cairo_classes.iter().map(|x| Felt(&x.0)),
        )?;

        s.serialize_iter(
            "declared_classes",
            self.0.declared_sierra_classes.len(),
            &mut self
                .0
                .declared_sierra_classes
                .iter()
                .map(|(k, v)| DeclaredClass {
                    class_hash: k,
                    casm_hash: v,
                }),
        )?;

        let mut deployed = self
            .0
            .contract_updates
            .iter()
            .filter_map(|(address, update)| {
                if let Some(ContractClassUpdate::Deploy(class)) = update.class.as_ref() {
                    Some(DeployedContractItem {
                        address,
                        class_hash: class,
                    })
                } else {
                    None
                }
            });
        let count = deployed.clone().count();
        s.serialize_iter("deployed_contracts", count, &mut deployed)?;

        let mut replaced = self
            .0
            .contract_updates
            .iter()
            .filter_map(|(address, update)| {
                if let Some(ContractClassUpdate::Replace(class)) = update.class.as_ref() {
                    Some(ReplacedClass { address, class })
                } else {
                    None
                }
            });
        let count = replaced.clone().count();
        s.serialize_iter("replaced_classes", count, &mut replaced)?;

        let mut nonces = self
            .0
            .contract_updates
            .iter()
            .filter_map(|(address, update)| {
                update
                    .nonce
                    .as_ref()
                    .map(|nonce| NonceUpdate { address, nonce })
            });
        let count = nonces.clone().count();
        s.serialize_iter("nonces", count, &mut nonces)?;

        s.end()
    }
}

impl SerializeForVersion for ContractStorageDiffItem<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        struct StorageEntry<'a> {
            key: &'a pathfinder_common::StorageAddress,
            value: &'a pathfinder_common::StorageValue,
        }

        impl SerializeForVersion for StorageEntry<'_> {
            fn serialize(
                &self,
                serializer: serialize::Serializer,
            ) -> Result<serialize::Ok, serialize::Error> {
                let mut serializer = serializer.serialize_struct()?;
                serializer.serialize_field("key", &Felt(self.key.get()))?;
                serializer.serialize_field("value", &Felt(&self.value.0))?;
                serializer.end()
            }
        }

        let mut s = serializer.serialize_struct()?;

        s.serialize_field("address", &Felt(self.address.get()))?;
        s.serialize_iter(
            "storage_entries",
            self.entries.len(),
            &mut self
                .entries
                .iter()
                .map(|(key, value)| StorageEntry { key, value }),
        )?;

        s.end()
    }
}

impl SerializeForVersion for DeployedContractItem<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("address", &Felt(self.address.get()))?;
        serializer.serialize_field("class_hash", &Felt(&self.class_hash.0))?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::serialize::Serializer;
    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;
    use serde_json::json;

    #[test]
    fn pending_state_update() {
        let s = Serializer::default();
        let state_update = test_state_update();

        let expected = json!({
            "old_root": s.serialize(&Felt(&state_update.parent_state_commitment.0)).unwrap(),
            "state_diff": s.serialize(&StateDiff(&state_update)).unwrap(),
        });

        let encoded = PendingStateUpdate(&state_update).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn state_diff() {
        let s = Serializer::default();

        let state_update = test_state_update();

        let mut storage_diffs = vec![];
        let mut deprecated_classes = vec![];
        let mut declared = vec![];
        let mut deployed = vec![];
        let mut replaced = vec![];
        let mut nonces = vec![];

        for (address, update) in &state_update.contract_updates {
            if !update.storage.is_empty() {
                storage_diffs.push(
                    ContractStorageDiffItem {
                        address,
                        entries: &update.storage,
                    }
                    .serialize(s)
                    .unwrap(),
                );
            }

            use pathfinder_common::state_update::ContractClassUpdate;
            match update.class.as_ref() {
                Some(ContractClassUpdate::Deploy(class_hash)) => deployed.push(
                    s.serialize(&DeployedContractItem {
                        address,
                        class_hash,
                    })
                    .unwrap(),
                ),
                Some(ContractClassUpdate::Replace(class)) => replaced.push(json!({
                    "contract_address": s.serialize(&Address(address)).unwrap(),
                    "class_hash": s.serialize(&Felt(&class.0)).unwrap(),
                })),
                None => {}
            }

            if let Some(nonce) = update.nonce.as_ref() {
                nonces.push(json!({
                    "nonce": s.serialize(&Felt(&nonce.0)).unwrap(),
                    "contract_address": s.serialize(&Address(address)).unwrap(),
                }));
            }
        }

        for (address, update) in &state_update.system_contract_updates {
            if !update.storage.is_empty() {
                storage_diffs.push(
                    ContractStorageDiffItem {
                        address,
                        entries: &update.storage,
                    }
                    .serialize(s)
                    .unwrap(),
                );
            }
        }

        for class in &state_update.declared_cairo_classes {
            deprecated_classes.push(Felt(&class.0).serialize(s).unwrap());
        }

        for (sierra, casm) in &state_update.declared_sierra_classes {
            {
                declared.push(json!({
                    "class_hash": s.serialize(&Felt(&sierra.0)).unwrap(),
                    "compiled_class_hash": s.serialize(&Felt(&casm.0)).unwrap(),
                }));
                ().serialize(s)
            }
            .unwrap();
        }

        let expected = json!({
            "storage_diffs": storage_diffs,
            "deprecated_declared_classes": deprecated_classes,
            "declared_classes": declared,
            "deployed_contracts": deployed,
            "replaced_classes": replaced,
            "nonces": nonces,
        });

        let encoded = StateDiff(&state_update).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    fn test_state_update() -> pathfinder_common::prelude::StateUpdate {
        let state_update = pathfinder_common::StateUpdate::default()
            .with_block_hash(block_hash_bytes!(b"block hash"))
            .with_state_commitment(state_commitment_bytes!(b"state commitment"))
            .with_parent_state_commitment(state_commitment_bytes!(b"parent commitment"))
            .with_storage_update(
                contract_address_bytes!(b"storage only"),
                storage_address_bytes!(b"storage key only"),
                storage_value_bytes!(b"storage value only"),
            )
            .with_contract_nonce(
                contract_address_bytes!(b"nonce only"),
                contract_nonce_bytes!(b"nonce nonce"),
            )
            // A contract with everything
            .with_storage_update(
                contract_address_bytes!(b"full address"),
                storage_address_bytes!(b"full key"),
                storage_value_bytes!(b"full value"),
            )
            .with_contract_nonce(
                contract_address_bytes!(b"full address"),
                contract_nonce_bytes!(b"full nonce"),
            )
            .with_deployed_contract(
                contract_address_bytes!(b"full address"),
                class_hash_bytes!(b"deployed class"),
            )
            .with_system_storage_update(
                contract_address!("0x1"),
                storage_address!("0x123"),
                storage_value!("0x444"),
            )
            .with_replaced_class(
                contract_address_bytes!(b"replaced address"),
                class_hash_bytes!(b"replaced class"),
            )
            .with_deployed_contract(
                contract_address_bytes!(b"deployed address"),
                class_hash_bytes!(b"deployed class"),
            );
        state_update
    }

    #[test]
    fn contract_storage_diff_item() {
        let s = Serializer::default();

        let address = contract_address!("0x123");
        let entries: HashMap<_, _> = [
            (storage_address!("0x1"), storage_value!("0xA")),
            (storage_address!("0x2"), storage_value!("0xB")),
            (storage_address!("0x3"), storage_value!("0xC")),
        ]
        .into();

        let expected = json!({
            "address": s.serialize(&Felt(address.get())).unwrap(),
            "storage_entries": entries.iter().map(|(k,v)| {
                json!({
                    "key": s.serialize(&Felt(k.get())).unwrap(),
                    "value": s.serialize(&Felt(&v.0)).unwrap(),
                })
            }).collect::<Vec<_>>(),
        });

        let encoded = ContractStorageDiffItem {
            address: &address,
            entries: &entries,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn deployed_contract_item() {
        let s = Serializer::default();

        let address = contract_address!("0x123");
        let class_hash = class_hash!("0x467");

        let expected = json!({
            "address": s.serialize(&Felt(address.get())).unwrap(),
            "class_hash": s.serialize(&Felt(&class_hash.0)).unwrap(),
        });

        let encoded = DeployedContractItem {
            address: &address,
            class_hash: &class_hash,
        }
        .serialize(s)
        .unwrap();

        assert_eq!(encoded, expected);
    }
}
