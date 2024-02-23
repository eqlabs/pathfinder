use pathfinder_common::GasPrice;

use crate::dto::serialize;
use crate::DefaultVersion;

pub struct BlockHeader<'a>(&'a pathfinder_common::BlockHeader);
pub struct ResourcePrice<'a> {
    price_in_fri: &'a GasPrice,
    price_in_wei: &'a GasPrice,
}

impl serialize::SerializeForVersion for BlockHeader<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let count = match serializer.version {
            DefaultVersion::V05 | DefaultVersion::V06 => 8,
            DefaultVersion::V07 => 10,
        };

        let mut s = serializer.serialize_struct("BLOCK_HEADER", count)?;

        s.serialize_field("block_hash", &self.0.hash)?;
        s.serialize_field("parent_hash", &self.0.parent_hash)?;
        s.serialize_field("block_number", &self.0.number)?;
        s.serialize_field("timestamp", &self.0.timestamp)?;
        s.serialize_field("new_root", &self.0.state_commitment)?;
        s.serialize_field("sequencer_address", &self.0.sequencer_address)?;
        s.serialize_field(
            "l1_gas_price",
            &ResourcePrice {
                price_in_fri: &self.0.strk_l1_gas_price,
                price_in_wei: &self.0.eth_l1_gas_price,
            },
        )?;
        s.serialize_field("block_hash", &self.0.hash)?;
        s.serialize_field("starknet_version", &self.0.starknet_version)?;

        if s.version == DefaultVersion::V07 {
            // This is an anonymous enum defined inside BLOCK_HEADER so we handle it inline.
            let l1_da_mode = match self.0.l1_da_mode {
                pathfinder_common::L1DataAvailabilityMode::Calldata => "CALLDATA",
                pathfinder_common::L1DataAvailabilityMode::Blob => "BLOB",
            };

            s.serialize_field("l1_da_mode", &l1_da_mode)?;
            s.serialize_field(
                "l1_data_gas_price",
                &ResourcePrice {
                    price_in_fri: &self.0.strk_l1_data_gas_price,
                    price_in_wei: &self.0.eth_l1_data_gas_price,
                },
            )?;
        }

        s.end()
    }
}

impl serialize::SerializeForVersion for ResourcePrice<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct("RESOURCE_PRICE", 2)?;

        serializer.serialize_field("price_in_fri", &self.price_in_fri)?;
        serializer.serialize_field("price_in_wei", &self.price_in_wei)?;

        serializer.end()
    }
}
