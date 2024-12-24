use pathfinder_common::{GasPrice, L1DataAvailabilityMode};
use serde::de::Error;

use crate::dto::SerializeStruct;
use crate::{Reorg, RpcVersion};

impl crate::dto::DeserializeForVersion for pathfinder_common::BlockId {
    fn deserialize(value: super::Value) -> Result<Self, serde_json::Error> {
        if value.is_string() {
            let value: String = value.deserialize()?;
            match value.as_str() {
                "latest" => Ok(Self::Latest),
                "pending" => Ok(Self::Pending),
                _ => Err(serde_json::Error::custom("Invalid block id")),
            }
        } else {
            value.deserialize_map(|value| {
                if value.contains_key("block_number") {
                    Ok(Self::Number(
                        pathfinder_common::BlockNumber::new(value.deserialize("block_number")?)
                            .ok_or_else(|| serde_json::Error::custom("Invalid block number"))?,
                    ))
                } else if value.contains_key("block_hash") {
                    Ok(Self::Hash(pathfinder_common::BlockHash(
                        value.deserialize("block_hash")?,
                    )))
                } else {
                    Err(serde_json::Error::custom("Invalid block id"))
                }
            })
        }
    }
}

impl crate::dto::SerializeForVersion for pathfinder_common::BlockHeader {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("block_hash", &self.hash)?;
        serializer.serialize_field("parent_hash", &self.parent_hash)?;
        serializer.serialize_field("block_number", &self.number.get())?;
        serializer.serialize_field("new_root", &self.state_commitment)?;
        serializer.serialize_field("timestamp", &self.timestamp.get())?;
        serializer.serialize_field("sequencer_address", &self.sequencer_address)?;
        serializer.serialize_field(
            "l1_gas_price",
            &ResourcePrice {
                price_in_wei: self.eth_l1_gas_price,
                price_in_fri: self.strk_l1_gas_price,
            },
        )?;
        serializer.serialize_field("starknet_version", &self.starknet_version.to_string())?;
        serializer.serialize_field(
            "l1_data_gas_price",
            &ResourcePrice {
                price_in_wei: self.eth_l1_data_gas_price,
                price_in_fri: self.strk_l1_data_gas_price,
            },
        )?;
        if serializer.version == RpcVersion::V08 {
            serializer.serialize_field(
                "l2_gas_price",
                &ResourcePrice {
                    price_in_wei: self.eth_l2_gas_price,
                    price_in_fri: self.strk_l2_gas_price,
                },
            )?;
        }
        serializer.serialize_field(
            "l1_da_mode",
            &match self.l1_da_mode {
                L1DataAvailabilityMode::Blob => "BLOB",
                L1DataAvailabilityMode::Calldata => "CALLDATA",
            },
        )?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for starknet_gateway_types::reply::PendingBlock {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("parent_hash", &self.parent_hash)?;
        serializer.serialize_field("timestamp", &self.timestamp.get())?;
        serializer.serialize_field("sequencer_address", &self.sequencer_address)?;
        serializer.serialize_field(
            "l1_gas_price",
            &ResourcePrice {
                price_in_wei: self.l1_gas_price.price_in_wei,
                price_in_fri: self.l1_gas_price.price_in_fri,
            },
        )?;
        serializer.serialize_field("starknet_version", &self.starknet_version.to_string())?;
        serializer.serialize_field(
            "l1_data_gas_price",
            &ResourcePrice {
                price_in_wei: self.l1_data_gas_price.price_in_wei,
                price_in_fri: self.l1_data_gas_price.price_in_fri,
            },
        )?;
        if serializer.version == RpcVersion::V08 {
            serializer.serialize_field(
                "l2_gas_price",
                &ResourcePrice {
                    price_in_wei: self.l2_gas_price.price_in_wei,
                    price_in_fri: self.l2_gas_price.price_in_fri,
                },
            )?;
        }
        serializer.serialize_field(
            "l1_da_mode",
            &match self.l1_da_mode {
                starknet_gateway_types::reply::L1DataAvailabilityMode::Blob => "BLOB",
                starknet_gateway_types::reply::L1DataAvailabilityMode::Calldata => "CALLDATA",
            },
        )?;
        serializer.end()
    }
}

#[derive(Debug)]
struct ResourcePrice {
    pub price_in_wei: GasPrice,
    pub price_in_fri: GasPrice,
}

impl crate::dto::SerializeForVersion for ResourcePrice {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("price_in_wei", &crate::dto::U128Hex(self.price_in_wei.0))?;
        serializer.serialize_field("price_in_fri", &crate::dto::U128Hex(self.price_in_fri.0))?;
        serializer.end()
    }
}

impl crate::dto::SerializeForVersion for Reorg {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("first_block_number", &self.first_block_number.get())?;
        serializer.serialize_field("first_block_hash", &self.first_block_hash)?;
        serializer.serialize_field("last_block_number", &self.last_block_number.get())?;
        serializer.serialize_field("last_block_hash", &self.last_block_hash)?;
        serializer.end()
    }
}
