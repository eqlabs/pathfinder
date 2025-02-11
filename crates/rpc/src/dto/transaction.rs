use pathfinder_common::transaction::TransactionVariant;
use pathfinder_common::TransactionHash;
use serde::de::Error;

use super::{DeserializeForVersion, U128Hex, U64Hex};
use crate::dto::{SerializeForVersion, Serializer};
use crate::{dto, RpcVersion};

pub struct TransactionWithHash<'a>(pub &'a pathfinder_common::transaction::Transaction);

impl SerializeForVersion for &pathfinder_common::transaction::Transaction {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut s = serializer.serialize_struct()?;
        match &self.variant {
            TransactionVariant::DeclareV0(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &tx.sender_address)?;
                s.serialize_field("max_fee", &tx.max_fee)?;
                s.serialize_field("version", &"0x0")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("class_hash", &tx.class_hash)?;
            }
            TransactionVariant::DeclareV1(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &tx.sender_address)?;
                s.serialize_field("max_fee", &tx.max_fee)?;
                s.serialize_field("version", &"0x1")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("class_hash", &tx.class_hash)?;
            }
            TransactionVariant::DeclareV2(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &tx.sender_address)?;
                s.serialize_field("compiled_class_hash", &tx.compiled_class_hash)?;
                s.serialize_field("max_fee", &tx.max_fee)?;
                s.serialize_field("version", &"0x2")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("class_hash", &tx.class_hash)?;
            }
            TransactionVariant::DeclareV3(tx) => {
                s.serialize_field("type", &"DECLARE")?;
                s.serialize_field("sender_address", &tx.sender_address)?;
                s.serialize_field("compiled_class_hash", &tx.compiled_class_hash)?;
                s.serialize_field("version", &"0x3")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("class_hash", &tx.class_hash)?;
                s.serialize_field("resource_bounds", &tx.resource_bounds)?;
                s.serialize_field("tip", &U64Hex(tx.tip.0))?;
                s.serialize_iter(
                    "paymaster_data",
                    tx.paymaster_data.len(),
                    &mut tx.paymaster_data.iter(),
                )?;
                s.serialize_iter(
                    "account_deployment_data",
                    tx.account_deployment_data.len(),
                    &mut tx.account_deployment_data.iter(),
                )?;
                s.serialize_field(
                    "nonce_data_availability_mode",
                    &tx.nonce_data_availability_mode,
                )?;
                s.serialize_field("fee_data_availability_mode", &tx.fee_data_availability_mode)?;
            }
            TransactionVariant::DeployV0(tx) => {
                s.serialize_field("version", &"0x0")?;
                s.serialize_field("type", &"DEPLOY")?;
                s.serialize_field("contract_address_salt", &tx.contract_address_salt)?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter(),
                )?;
                s.serialize_field("class_hash", &tx.class_hash)?;
            }
            TransactionVariant::DeployV1(tx) => {
                s.serialize_field("version", &"0x1")?;
                s.serialize_field("type", &"DEPLOY")?;
                s.serialize_field("contract_address_salt", &tx.contract_address_salt)?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter(),
                )?;
                s.serialize_field("class_hash", &tx.class_hash)?;
            }
            TransactionVariant::DeployAccountV1(tx) => {
                s.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                s.serialize_field("max_fee", &tx.max_fee)?;
                s.serialize_field("version", &"0x1")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("contract_address_salt", &tx.contract_address_salt)?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter(),
                )?;
                s.serialize_field("class_hash", &tx.class_hash)?;
            }
            TransactionVariant::DeployAccountV3(tx) => {
                s.serialize_field("type", &"DEPLOY_ACCOUNT")?;
                s.serialize_field("version", &"0x3")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("contract_address_salt", &tx.contract_address_salt)?;
                s.serialize_iter(
                    "constructor_calldata",
                    tx.constructor_calldata.len(),
                    &mut tx.constructor_calldata.iter(),
                )?;
                s.serialize_field("class_hash", &tx.class_hash)?;
                s.serialize_field("resource_bounds", &tx.resource_bounds)?;
                s.serialize_field("tip", &U64Hex(tx.tip.0))?;
                s.serialize_iter(
                    "paymaster_data",
                    tx.paymaster_data.len(),
                    &mut tx.paymaster_data.iter(),
                )?;
                s.serialize_field(
                    "nonce_data_availability_mode",
                    &tx.nonce_data_availability_mode,
                )?;
                s.serialize_field("fee_data_availability_mode", &tx.fee_data_availability_mode)?;
            }
            TransactionVariant::InvokeV0(tx) => {
                s.serialize_field("type", &"INVOKE")?;
                s.serialize_field("max_fee", &tx.max_fee)?;
                s.serialize_field("version", &"0x0")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("contract_address", &tx.sender_address)?;
                s.serialize_field("entry_point_selector", &tx.entry_point_selector)?;
                s.serialize_iter("calldata", tx.calldata.len(), &mut tx.calldata.iter())?;
            }
            TransactionVariant::InvokeV1(tx) => {
                s.serialize_field("type", &"INVOKE")?;
                s.serialize_field("sender_address", &tx.sender_address)?;
                s.serialize_iter("calldata", tx.calldata.len(), &mut tx.calldata.iter())?;
                s.serialize_field("max_fee", &tx.max_fee)?;
                s.serialize_field("version", &"0x1")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
            }
            TransactionVariant::InvokeV3(tx) => {
                s.serialize_field("type", &"INVOKE")?;
                s.serialize_field("sender_address", &tx.sender_address)?;
                s.serialize_iter("calldata", tx.calldata.len(), &mut tx.calldata.iter())?;
                s.serialize_field("version", &"0x3")?;
                s.serialize_iter("signature", tx.signature.len(), &mut tx.signature.iter())?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("resource_bounds", &tx.resource_bounds)?;
                s.serialize_field("tip", &U64Hex(tx.tip.0))?;
                s.serialize_iter(
                    "paymaster_data",
                    tx.paymaster_data.len(),
                    &mut tx.paymaster_data.iter(),
                )?;
                s.serialize_iter(
                    "account_deployment_data",
                    tx.account_deployment_data.len(),
                    &mut tx.account_deployment_data.iter(),
                )?;
                s.serialize_field(
                    "nonce_data_availability_mode",
                    &tx.nonce_data_availability_mode,
                )?;
                s.serialize_field("fee_data_availability_mode", &tx.fee_data_availability_mode)?;
            }
            TransactionVariant::L1Handler(tx) => {
                s.serialize_field("version", &"0x0")?;
                s.serialize_field("type", &"L1_HANDLER")?;
                s.serialize_field("nonce", &tx.nonce)?;
                s.serialize_field("contract_address", &tx.contract_address)?;
                s.serialize_field("entry_point_selector", &tx.entry_point_selector)?;
                s.serialize_iter("calldata", tx.calldata.len(), &mut tx.calldata.iter())?;
            }
        }
        s.end()
    }
}

impl SerializeForVersion for TransactionWithHash<'_> {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut s = serializer.serialize_struct()?;
        s.serialize_field("transaction_hash", &self.0.hash)?;
        s.flatten(&self.0)?;
        s.end()
    }
}

impl SerializeForVersion for pathfinder_common::transaction::ResourceBounds {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("l1_gas", &self.l1_gas)?;
        serializer.serialize_field("l2_gas", &self.l2_gas)?;
        if serializer.version >= RpcVersion::V08 {
            // `l1_data_gas` is serialized as (0, 0) in v0.8+ even if it's not set
            // See https://github.com/eqlabs/pathfinder/issues/2571
            serializer.serialize_field("l1_data_gas", &self.l1_data_gas.unwrap_or_default())?;
        }
        serializer.end()
    }
}

impl DeserializeForVersion for pathfinder_common::transaction::ResourceBounds {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        let version = value.version;
        value.deserialize_map(|value| {
            Ok(Self {
                l1_gas: value.deserialize("l1_gas")?,
                l2_gas: value.deserialize("l2_gas")?,
                l1_data_gas: if version >= RpcVersion::V08 {
                    // `l1_data_gas` is *required* in v0.8+
                    // See https://github.com/eqlabs/pathfinder/issues/2571
                    Some(value.deserialize("l1_data_gas")?)
                } else {
                    None
                },
            })
        })
    }
}

impl SerializeForVersion for pathfinder_common::transaction::ResourceBound {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("max_amount", &self.max_amount)?;
        serializer.serialize_field("max_price_per_unit", &self.max_price_per_unit)?;
        serializer.end()
    }
}

impl DeserializeForVersion for pathfinder_common::transaction::ResourceBound {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                max_amount: pathfinder_common::ResourceAmount(
                    value.deserialize::<U64Hex>("max_amount")?.0,
                ),
                max_price_per_unit: pathfinder_common::ResourcePricePerUnit(
                    value.deserialize::<U128Hex>("max_price_per_unit")?.0,
                ),
            })
        })
    }
}

impl SerializeForVersion for pathfinder_common::transaction::DataAvailabilityMode {
    fn serialize(&self, serializer: Serializer) -> Result<crate::dto::Ok, crate::dto::Error> {
        match self {
            pathfinder_common::transaction::DataAvailabilityMode::L1 => {
                serializer.serialize_str("L1")
            }
            pathfinder_common::transaction::DataAvailabilityMode::L2 => {
                serializer.serialize_str("L2")
            }
        }
    }
}

impl DeserializeForVersion for pathfinder_common::transaction::DataAvailabilityMode {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        let value: String = value.deserialize()?;
        match value.as_str() {
            "L1" => Ok(Self::L1),
            "L2" => Ok(Self::L2),
            _ => Err(serde_json::Error::custom("invalid data availability mode")),
        }
    }
}

impl DeserializeForVersion for pathfinder_common::TransactionIndex {
    fn deserialize(value: dto::Value) -> Result<Self, serde_json::Error> {
        let idx = value.deserialize()?;
        Self::new(idx).ok_or_else(|| serde_json::Error::custom("Invalid transaction index"))
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::transaction::{ResourceBound, ResourceBounds};
    use pathfinder_common::{ResourceAmount, ResourcePricePerUnit};
    use serde_json::json;
    use starknet_api::transaction::fields::Resource;

    use crate::dto::{SerializeForVersion, Serializer};
    use crate::RpcVersion;

    #[test]
    fn resource_bounds() {
        let resource_bounds = ResourceBounds {
            l1_gas: ResourceBound {
                max_amount: ResourceAmount(1),
                max_price_per_unit: ResourcePricePerUnit(2),
            },
            l2_gas: ResourceBound {
                max_amount: ResourceAmount(3),
                max_price_per_unit: ResourcePricePerUnit(4),
            },
            l1_data_gas: Some(ResourceBound {
                max_amount: ResourceAmount(5),
                max_price_per_unit: ResourcePricePerUnit(6),
            }),
        };

        pretty_assertions_sorted::assert_eq!(
            resource_bounds
                .serialize(Serializer::new(RpcVersion::V06))
                .unwrap(),
            json!({
                "l1_gas": {
                    "max_amount": "0x1",
                    "max_price_per_unit": "0x2",
                },
                "l2_gas": {
                    "max_amount": "0x3",
                    "max_price_per_unit": "0x4",
                },
            })
        );

        pretty_assertions_sorted::assert_eq!(
            resource_bounds
                .serialize(Serializer::new(RpcVersion::V07))
                .unwrap(),
            json!({
                "l1_gas": {
                    "max_amount": "0x1",
                    "max_price_per_unit": "0x2",
                },
                "l2_gas": {
                    "max_amount": "0x3",
                    "max_price_per_unit": "0x4",
                },
            })
        );

        pretty_assertions_sorted::assert_eq!(
            resource_bounds
                .serialize(Serializer::new(RpcVersion::V08))
                .unwrap(),
            json!({
                "l1_gas": {
                    "max_amount": "0x1",
                    "max_price_per_unit": "0x2",
                },
                "l2_gas": {
                    "max_amount": "0x3",
                    "max_price_per_unit": "0x4",
                },
                "l1_data_gas": {
                    "max_amount": "0x5",
                    "max_price_per_unit": "0x6",
                },
            })
        );
    }
}
