use pathfinder_common::{GasPrice, L1DataAvailabilityMode};
use serde::de::Error;

use super::serialize::SerializeStruct;
use crate::Reorg;

#[derive(Debug)]
pub struct BlockHeader<'a>(pub &'a pathfinder_common::BlockHeader);

#[derive(Debug)]
pub struct PendingBlockHeader<'a>(pub &'a starknet_gateway_types::reply::PendingBlock);

impl crate::dto::DeserializeForVersion for pathfinder_common::BlockId {
    fn deserialize(value: super::Value) -> Result<Self, serde_json::Error> {
        if value.is_string() {
            let value: String = value.deserialize_serde()?;
            match value.as_str() {
                "latest" => Ok(Self::Latest),
                "pending" => Ok(Self::Pending),
                _ => Err(serde_json::Error::custom("Invalid block id")),
            }
        } else {
            value.deserialize_map(|value| {
                if value.contains_key("block_number") {
                    Ok(Self::Number(
                        pathfinder_common::BlockNumber::new(
                            value.deserialize_serde("block_number")?,
                        )
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

impl crate::dto::serialize::SerializeForVersion for BlockHeader<'_> {
    fn serialize(
        &self,
        serializer: super::serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("block_hash", &crate::dto::Felt(&self.0.hash.0))?;
        serializer.serialize_field("parent_hash", &crate::dto::Felt(&self.0.parent_hash.0))?;
        serializer.serialize_field("block_number", &self.0.number.get())?;
        serializer.serialize_field("new_root", &crate::dto::Felt(&self.0.state_commitment.0))?;
        serializer.serialize_field("timestamp", &self.0.timestamp.get())?;
        serializer.serialize_field(
            "sequencer_address",
            &crate::dto::Felt(&self.0.sequencer_address.0),
        )?;
        serializer.serialize_field(
            "l1_gas_price",
            &ResourcePrice {
                price_in_wei: self.0.eth_l1_gas_price,
                price_in_fri: self.0.strk_l1_gas_price,
            },
        )?;
        serializer.serialize_field("starknet_version", &self.0.starknet_version.to_string())?;
        serializer.serialize_field(
            "l1_data_gas_price",
            &ResourcePrice {
                price_in_wei: self.0.eth_l1_data_gas_price,
                price_in_fri: self.0.strk_l1_data_gas_price,
            },
        )?;
        serializer.serialize_field(
            "l1_da_mode",
            &match self.0.l1_da_mode {
                L1DataAvailabilityMode::Blob => "BLOB",
                L1DataAvailabilityMode::Calldata => "CALLDATA",
            },
        )?;
        serializer.end()
    }
}

impl crate::dto::serialize::SerializeForVersion for PendingBlockHeader<'_> {
    fn serialize(
        &self,
        serializer: super::serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("parent_hash", &crate::dto::Felt(&self.0.parent_hash.0))?;
        serializer.serialize_field("timestamp", &self.0.timestamp.get())?;
        serializer.serialize_field(
            "sequencer_address",
            &crate::dto::Felt(&self.0.sequencer_address.0),
        )?;
        serializer.serialize_field(
            "l1_gas_price",
            &ResourcePrice {
                price_in_wei: self.0.l1_gas_price.price_in_wei,
                price_in_fri: self.0.l1_gas_price.price_in_fri,
            },
        )?;
        serializer.serialize_field("starknet_version", &self.0.starknet_version.to_string())?;
        serializer.serialize_field(
            "l1_data_gas_price",
            &ResourcePrice {
                price_in_wei: self.0.l1_data_gas_price.price_in_wei,
                price_in_fri: self.0.l1_data_gas_price.price_in_fri,
            },
        )?;
        serializer.serialize_field(
            "l1_da_mode",
            &match self.0.l1_da_mode {
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

impl crate::dto::serialize::SerializeForVersion for ResourcePrice {
    fn serialize(
        &self,
        serializer: super::serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("price_in_wei", &crate::dto::U128Hex(self.price_in_wei.0))?;
        serializer.serialize_field("price_in_fri", &crate::dto::U128Hex(self.price_in_fri.0))?;
        serializer.end()
    }
}

impl crate::dto::serialize::SerializeForVersion for Reorg {
    fn serialize(
        &self,
        serializer: super::serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("first_block_number", &self.first_block_number.get())?;
        serializer.serialize_field(
            "first_block_hash",
            &crate::dto::Felt(&self.first_block_hash.0),
        )?;
        serializer.serialize_field("last_block_number", &self.last_block_number.get())?;
        serializer.serialize_field(
            "last_block_hash",
            &crate::dto::Felt(&self.last_block_hash.0),
        )?;
        serializer.end()
    }
}
