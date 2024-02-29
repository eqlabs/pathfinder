use crate::dto;
use crate::dto::serialize;

pub struct BlockHeader<'a>(&'a pathfinder_common::BlockHeader);

pub struct ResourcePrice<'a> {
    price_in_fri: &'a pathfinder_common::GasPrice,
    price_in_wei: &'a pathfinder_common::GasPrice,
}

// This is an anonymous enum defined inside BLOCK_HEADER v0.7.
struct L1DaMode(pathfinder_common::L1DataAvailabilityMode);

impl serialize::SerializeForVersion for BlockHeader<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut s = serializer.serialize_struct()?;

        s.serialize_field("block_hash", &dto::BlockHash(&self.0.hash))?;
        s.serialize_field("parent_hash", &dto::BlockHash(&self.0.parent_hash))?;
        s.serialize_field("block_number", &dto::BlockNumber(self.0.number))?;
        s.serialize_field(
            "timestamp",
            &serializer.serialize_u64(self.0.timestamp.get())?,
        )?;
        s.serialize_field("new_root", &dto::Felt(&self.0.state_commitment.0))?;
        s.serialize_field("sequencer_address", &dto::Felt(&self.0.sequencer_address.0))?;
        s.serialize_field(
            "l1_gas_price",
            &ResourcePrice {
                price_in_fri: &self.0.strk_l1_gas_price,
                price_in_wei: &self.0.eth_l1_gas_price,
            },
        )?;
        s.serialize_field(
            "starknet_version",
            &serializer.serialize_str(self.0.starknet_version.as_str())?,
        )?;

        s.serialize_field("l1_da_mode", &L1DaMode(self.0.l1_da_mode))?;
        s.serialize_field(
            "l1_data_gas_price",
            &ResourcePrice {
                price_in_fri: &self.0.strk_l1_data_gas_price,
                price_in_wei: &self.0.eth_l1_data_gas_price,
            },
        )?;

        s.end()
    }
}

impl serialize::SerializeForVersion for L1DaMode {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let s = match self.0 {
            pathfinder_common::L1DataAvailabilityMode::Calldata => "CALLDATA",
            pathfinder_common::L1DataAvailabilityMode::Blob => "BLOB",
        };
        serializer.serialize_str(s)
    }
}

impl serialize::SerializeForVersion for ResourcePrice<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<super::serialize::Ok, super::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;

        // unwraps are safe as u128 always fit into a felt.
        let fri = self.price_in_fri.0.to_be_bytes();
        let fri = pathfinder_crypto::Felt::from_be_slice(&fri).unwrap();
        let wei = self.price_in_wei.0.to_be_bytes();
        let wei = pathfinder_crypto::Felt::from_be_slice(&wei).unwrap();

        serializer.serialize_field("price_in_fri", &dto::Felt(&fri))?;
        serializer.serialize_field("price_in_wei", &dto::Felt(&wei))?;

        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::serialize::SerializeForVersion;
    use crate::dto::serialize::Serializer;
    use crate::dto::*;
    use pathfinder_common::macro_prelude::*;
    use serde_json::json;

    use pretty_assertions_sorted::assert_eq;

    #[test]
    fn header() {
        let s = Serializer::default();

        let header = pathfinder_common::BlockHeader {
            hash: block_hash!("0x1"),
            parent_hash: block_hash!("0x2"),
            number: pathfinder_common::BlockNumber::new_or_panic(3),
            timestamp: pathfinder_common::BlockTimestamp::new_or_panic(4),
            eth_l1_gas_price: pathfinder_common::GasPrice(5),
            strk_l1_gas_price: pathfinder_common::GasPrice(6),
            eth_l1_data_gas_price: pathfinder_common::GasPrice(7),
            strk_l1_data_gas_price: pathfinder_common::GasPrice(8),
            sequencer_address: sequencer_address!("0x9"),
            starknet_version: pathfinder_common::StarknetVersion::new(0, 11, 1),
            class_commitment: class_commitment!("0x10"),
            event_commitment: event_commitment!("0x11"),
            state_commitment: state_commitment!("0x12"),
            storage_commitment: storage_commitment!("0x13"),
            transaction_commitment: transaction_commitment!("0x14"),
            transaction_count: 15,
            event_count: 16,
            l1_da_mode: pathfinder_common::L1DataAvailabilityMode::Blob,
        };
        let expected = json!({
            "block_hash": s.serialize(&BlockHash(&header.hash)).unwrap(),
            "parent_hash": s.serialize(&BlockHash(&header.parent_hash)).unwrap(),
            "block_number": s.serialize(&BlockNumber(header.number)).unwrap(),
            "timestamp": s.serialize_u64(header.timestamp.get()).unwrap(),
            "new_root": s.serialize(&Felt(&header.state_commitment.0)).unwrap(),
            "sequencer_address": s.serialize(&Felt(&header.sequencer_address.0)).unwrap(),
            "starknet_version": s.serialize_str(header.starknet_version.as_str()).unwrap(),
            "l1_da_mode": s.serialize(&L1DaMode(header.l1_da_mode)).unwrap(),
            "l1_gas_price": s.serialize(&ResourcePrice {
                price_in_fri: &header.strk_l1_gas_price,
                price_in_wei: &header.eth_l1_gas_price,
            }).unwrap(),
            "l1_data_gas_price": s.serialize(&ResourcePrice {
                price_in_fri: &header.strk_l1_data_gas_price,
                price_in_wei: &header.eth_l1_data_gas_price,
            }).unwrap(),
        });

        let encoded = s.serialize(&BlockHeader(&header)).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn resource_price() {
        let expected = json!({
            "price_in_fri": Felt(&felt!("0x1234")).serialize(Default::default()).unwrap(),
            "price_in_wei": Felt(&felt!("0x5678")).serialize(Default::default()).unwrap(),
        });

        let encoded = ResourcePrice {
            price_in_fri: &pathfinder_common::GasPrice(0x1234),
            price_in_wei: &pathfinder_common::GasPrice(0x5678),
        }
        .serialize(Default::default())
        .unwrap();

        assert_eq!(encoded, expected);
    }
}
