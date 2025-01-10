use pathfinder_common::prelude::*;
use pathfinder_common::GasPriceHex;
pub struct Header {
    block_hash: BlockHash,
    parent_hash: BlockHash,
    block_number: BlockNumber,
    new_root: StateCommitment,
    timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    l1_gas_price: ResourcePrice,
    starknet_version: StarknetVersion,
    l1_data_gas_price: ResourcePrice,
    l1_da_mode: L1DaMode,
}

impl crate::dto::SerializeForVersion for Header {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("block_hash", &self.block_hash)?;
        serializer.serialize_field("parent_hash", &self.parent_hash)?;
        serializer.serialize_field("block_number", &self.block_number)?;
        serializer.serialize_field("new_root", &self.new_root)?;
        serializer.serialize_field("timestamp", &self.timestamp)?;
        serializer.serialize_field("sequencer_address", &self.sequencer_address)?;
        serializer.serialize_field("l1_gas_price", &self.l1_gas_price)?;
        serializer.serialize_field("starknet_version", &self.starknet_version)?;
        serializer.serialize_field("l1_data_gas_price", &self.l1_data_gas_price)?;
        serializer.serialize_field("l1_da_mode", &self.l1_da_mode)?;
        serializer.end()
    }
}

impl From<pathfinder_common::BlockHeader> for Header {
    fn from(value: pathfinder_common::BlockHeader) -> Self {
        let l1_gas_price = ResourcePrice {
            price_in_wei: value.eth_l1_gas_price,
            price_in_fri: value.strk_l1_gas_price,
        };
        let l1_data_gas_price = ResourcePrice {
            price_in_wei: value.eth_l1_data_gas_price,
            price_in_fri: value.strk_l1_data_gas_price,
        };

        Self {
            block_hash: value.hash,
            parent_hash: value.parent_hash,
            block_number: value.number,
            new_root: value.state_commitment,
            timestamp: value.timestamp,
            sequencer_address: value.sequencer_address,
            l1_gas_price,
            starknet_version: value.starknet_version,
            l1_data_gas_price,
            l1_da_mode: value.l1_da_mode.into(),
        }
    }
}

pub struct PendingHeader {
    parent_hash: BlockHash,
    timestamp: BlockTimestamp,
    sequencer_address: SequencerAddress,
    l1_gas_price: ResourcePrice,
    starknet_version: StarknetVersion,
    l1_data_gas_price: ResourcePrice,
    l1_da_mode: L1DaMode,
}

impl From<pathfinder_common::BlockHeader> for PendingHeader {
    fn from(value: pathfinder_common::BlockHeader) -> Self {
        let l1_gas_price = ResourcePrice {
            price_in_wei: value.eth_l1_gas_price,
            price_in_fri: value.strk_l1_gas_price,
        };
        let l1_data_gas_price = ResourcePrice {
            price_in_wei: value.eth_l1_data_gas_price,
            price_in_fri: value.strk_l1_data_gas_price,
        };

        Self {
            parent_hash: value.parent_hash,
            timestamp: value.timestamp,
            sequencer_address: value.sequencer_address,
            l1_gas_price,
            starknet_version: value.starknet_version,
            l1_data_gas_price,
            l1_da_mode: value.l1_da_mode.into(),
        }
    }
}

impl crate::dto::SerializeForVersion for PendingHeader {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("parent_hash", &self.parent_hash)?;
        serializer.serialize_field("timestamp", &self.timestamp)?;
        serializer.serialize_field("sequencer_address", &self.sequencer_address)?;
        serializer.serialize_field("l1_gas_price", &self.l1_gas_price)?;
        serializer.serialize_field("starknet_version", &self.starknet_version)?;
        serializer.serialize_field("l1_data_gas_price", &self.l1_data_gas_price)?;
        serializer.serialize_field("l1_da_mode", &self.l1_da_mode)?;
        serializer.end()
    }
}

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
        serializer.serialize_field("price_in_wei", &GasPriceHex(self.price_in_wei))?;
        serializer.serialize_field("price_in_fri", &GasPriceHex(self.price_in_fri))?;
        serializer.end()
    }
}

enum L1DaMode {
    Blob,
    Calldata,
}

impl From<pathfinder_common::L1DataAvailabilityMode> for L1DaMode {
    fn from(value: pathfinder_common::L1DataAvailabilityMode) -> Self {
        match value {
            pathfinder_common::L1DataAvailabilityMode::Calldata => Self::Calldata,
            pathfinder_common::L1DataAvailabilityMode::Blob => Self::Blob,
        }
    }
}

impl crate::dto::SerializeForVersion for L1DaMode {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        serializer.serialize_str(match self {
            L1DaMode::Blob => "BLOB",
            L1DaMode::Calldata => "CALLDATA",
        })
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{BlockNumber, BlockTimestamp, GasPrice, StarknetVersion};
    use pretty_assertions_sorted::assert_eq;
    use serde_json::json;

    use super::*;
    use crate::dto::SerializeForVersion;

    #[test]
    fn pending_header() {
        let expected = json!({
            "parent_hash": "0x2",
            "timestamp": 4,
            "sequencer_address": "0x9",
            "l1_gas_price": {
                "price_in_wei": "0x5",
                "price_in_fri": "0x6",
            },
            "l1_data_gas_price": {
                "price_in_wei": "0x7",
                "price_in_fri": "0x8",
            },
            "l1_da_mode": "CALLDATA",
            "starknet_version": "0.11.1"
        });

        let uut = pathfinder_common::BlockHeader {
            parent_hash: block_hash!("0x2"),
            timestamp: BlockTimestamp::new_or_panic(4),
            eth_l1_gas_price: GasPrice(0x5),
            strk_l1_gas_price: GasPrice(0x6),
            eth_l1_data_gas_price: GasPrice(0x7),
            strk_l1_data_gas_price: GasPrice(0x8),
            sequencer_address: sequencer_address!("0x9"),
            starknet_version: StarknetVersion::new(0, 11, 1, 0),
            l1_da_mode: pathfinder_common::L1DataAvailabilityMode::Calldata,
            ..Default::default()
        };
        let uut = PendingHeader::from(uut);
        let encoded = uut
            .serialize(crate::dto::Serializer::new(crate::RpcVersion::V07))
            .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn header() {
        let expected = json!({
            "block_hash": "0x1",
            "parent_hash": "0x2",
            "block_number": 3,
            "new_root": "0x10",
            "timestamp": 4,
            "sequencer_address": "0x9",
            "l1_gas_price": {
                "price_in_wei": "0x5",
                "price_in_fri": "0x6",
            },
            "l1_data_gas_price": {
                "price_in_wei": "0x7",
                "price_in_fri": "0x8",
            },
            "l1_da_mode": "CALLDATA",
            "starknet_version": "0.11.1"
        });

        let uut = pathfinder_common::BlockHeader {
            hash: block_hash!("0x1"),
            parent_hash: block_hash!("0x2"),
            number: BlockNumber::new_or_panic(3),
            timestamp: BlockTimestamp::new_or_panic(4),
            eth_l1_gas_price: GasPrice(0x5),
            strk_l1_gas_price: GasPrice(0x6),
            eth_l1_data_gas_price: GasPrice(0x7),
            strk_l1_data_gas_price: GasPrice(0x8),
            sequencer_address: sequencer_address!("0x9"),
            state_commitment: state_commitment!("0x10"),
            starknet_version: StarknetVersion::new(0, 11, 1, 0),
            l1_da_mode: pathfinder_common::L1DataAvailabilityMode::Calldata,
            ..Default::default()
        };
        let uut = Header::from(uut);
        let encoded = uut
            .serialize(crate::dto::Serializer::new(crate::RpcVersion::V07))
            .unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn l1_data_availability_mode() {
        let calldata = L1DaMode::from(pathfinder_common::L1DataAvailabilityMode::Calldata);
        let encoded = calldata
            .serialize(crate::dto::Serializer::new(crate::RpcVersion::V07))
            .unwrap();
        assert_eq!(encoded, json!("CALLDATA"));

        let blob = L1DaMode::from(pathfinder_common::L1DataAvailabilityMode::Blob);
        let encoded = blob
            .serialize(crate::dto::Serializer::new(crate::RpcVersion::V07))
            .unwrap();
        assert_eq!(encoded, json!("BLOB"));
    }

    #[test]
    fn resource_price() {
        let expected = json!({
            "price_in_fri": "0x123",
            "price_in_wei": "0x456",
        });

        let uut = ResourcePrice {
            price_in_wei: GasPrice(0x456),
            price_in_fri: GasPrice(0x123),
        };

        let encoded = uut
            .serialize(crate::dto::Serializer::new(crate::RpcVersion::V07))
            .unwrap();

        assert_eq!(encoded, expected);
    }
}
