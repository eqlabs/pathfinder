use pathfinder_common::GasPrice;
use serde::ser::SerializeStruct;
use serde::Serializer;

use crate::dto::SerializeForVersion;
use crate::DefaultVersion;

pub struct BlockHeader<'a>(&'a pathfinder_common::BlockHeader);
pub struct ResourcePrice<'a> {
    price_in_fri: &'a GasPrice,
    price_in_wei: &'a GasPrice,
}

impl SerializeForVersion for BlockHeader<'_> {
    fn serialize(&self, v: DefaultVersion) -> serde_json::Result<serde_json::Value> {
        let x = &self.0;
        let serializer = serde_json::value::Serializer;

        let count = match v {
            DefaultVersion::V05 | DefaultVersion::V06 => 8,
            DefaultVersion::V07 => 10,
        };

        let mut s = serializer.serialize_struct("BLOCK_HEADER", count)?;

        x.hash.serialize_struct_field(v, "block_hash", &mut s)?;
        x.parent_hash
            .serialize_struct_field(v, "parent_hash", &mut s)?;
        x.number.serialize_struct_field(v, "block_number", &mut s)?;
        x.state_commitment
            .serialize_struct_field(v, "new_root", &mut s)?;
        x.timestamp.serialize_struct_field(v, "timestamp", &mut s)?;
        x.sequencer_address
            .serialize_struct_field(v, "sequencer_address", &mut s)?;
        ResourcePrice {
            price_in_fri: &x.strk_l1_gas_price,
            price_in_wei: &x.eth_l1_gas_price,
        }
        .serialize_struct_field(v, "l1_gas_price", &mut s)?;
        x.starknet_version
            .serialize_struct_field(v, "starknet_version", &mut s)?;

        if v == DefaultVersion::V07 {
            // This is an anonymous enum defined inside BLOCK_HEADER so we handle it inline.
            let l1_da_mode = match x.l1_da_mode {
                pathfinder_common::L1DataAvailabilityMode::Calldata => "CALLDATA",
                pathfinder_common::L1DataAvailabilityMode::Blob => "BLOB",
            };

            l1_da_mode.serialize_struct_field(v, "l1_da_mode", &mut s)?;
            ResourcePrice {
                price_in_fri: &x.strk_l1_data_gas_price,
                price_in_wei: &x.eth_l1_data_gas_price,
            }
            .serialize_struct_field(v, "l1_data_gas_price", &mut s)?;
        }

        s.end()
    }
}

impl SerializeForVersion for ResourcePrice<'_> {
    fn serialize(&self, v: DefaultVersion) -> Result<serde_json::Value, serde_json::Error> {
        let mut serializer = serde_json::value::Serializer.serialize_struct("RESOURCE_PRICE", 2)?;

        self.price_in_fri
            .serialize_struct_field(v, "price_in_fri", &mut serializer)?;
        self.price_in_wei
            .serialize_struct_field(v, "price_in_wei", &mut serializer)?;

        serializer.end()
    }
}
