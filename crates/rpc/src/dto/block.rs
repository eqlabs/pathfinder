use pathfinder_common::{GasPrice, L1DataAvailabilityMode};

use super::serialize::SerializeStruct;

#[derive(Debug)]
pub struct BlockHeader<'a>(pub &'a pathfinder_common::BlockHeader);

#[derive(Debug)]
pub struct PendingBlockHeader<'a>(pub &'a starknet_gateway_types::reply::PendingBlock);

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
        serializer.serialize_field(
            "price_in_wei",
            &crate::dto::NumAsHex::U128(self.price_in_wei.0),
        )?;
        serializer.serialize_field(
            "price_in_fri",
            &crate::dto::NumAsHex::U128(self.price_in_fri.0),
        )?;
        serializer.end()
    }
}
