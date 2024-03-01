use std::collections::HashMap;

use crate::dto::*;

use super::serialize::SerializeForVersion;

pub struct ContractStorageDiffItem<'a> {
    address: &'a pathfinder_common::ContractAddress,
    entries: &'a HashMap<pathfinder_common::StorageAddress, pathfinder_common::StorageValue>,
}

pub struct DeployedContractItem<'a> {
    address: &'a pathfinder_common::ContractAddress,
    class_hash: &'a pathfinder_common::ClassHash,
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
    use serde_json::json;

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
