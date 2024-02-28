use primitive_types::H256;

use crate::dto::serialize;

use super::serialize::SerializeForVersion;

pub struct SyncStatus<'a>(pub &'a crate::v02::types::syncing::Status);

pub struct Felt<'a>(pub &'a pathfinder_crypto::Felt);
pub struct BlockHash<'a>(pub &'a pathfinder_common::BlockHash);
pub struct Address<'a>(pub &'a pathfinder_common::ContractAddress);
pub struct TxnHash<'a>(pub &'a pathfinder_common::TransactionHash);
pub struct ChainId<'a>(pub &'a pathfinder_common::ChainId);

pub struct EthAddress<'a>(pub &'a pathfinder_common::EthereumAddress);
pub struct StorageKey<'a>(pub &'a pathfinder_common::StorageAddress);
pub struct BlockNumber(pub pathfinder_common::BlockNumber);

pub struct U64(pub u64);
pub struct U128(pub u128);

mod hex_str {
    use std::borrow::Cow;

    pub fn bytes_to_hex_str_stripped(data: &[u8]) -> Cow<'static, str> {
        let zero_count = data.iter().take_while(|b| **b == 0).count();
        let data = &data[zero_count..];

        if data.is_empty() {
            return Cow::from("0x0");
        }

        return bytes_to_hex_str_full(data).into();
    }

    pub fn bytes_to_hex_str_full(data: &[u8]) -> String {
        const LUT: [u8; 16] = *b"0123456789abcdef";

        let mut buf = vec![0; 2 + data.len() * 2];
        buf[0] = b'0';
        buf[1] = b'x';
        // Same small lookup table is ~25% faster than hex::encode_from_slice 🤷
        for (i, b) in data.into_iter().enumerate() {
            let idx = *b as usize;
            let pos = 2 + i * 2;
            let x = [LUT[(idx & 0xf0) >> 4], LUT[idx & 0x0f]];
            buf[pos..pos + 2].copy_from_slice(&x);
        }

        // SAFETY: we only insert hex digits.
        unsafe { String::from_utf8_unchecked(buf) }
    }
}

impl SerializeForVersion for SyncStatus<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("starting_block_hash", &BlockHash(&self.0.starting.hash))?;
        serializer.serialize_field("starting_block_num", &BlockNumber(self.0.starting.number))?;
        serializer.serialize_field("current_block_hash", &BlockHash(&self.0.current.hash))?;
        serializer.serialize_field("current_block_num", &BlockNumber(self.0.current.number))?;
        serializer.serialize_field("highest_block_hash", &BlockHash(&self.0.highest.hash))?;
        serializer.serialize_field("highest_block_num", &BlockNumber(self.0.highest.number))?;
        serializer.end()
    }
}

impl SerializeForVersion for Felt<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let hex_str = hex_str::bytes_to_hex_str_stripped(self.0.as_be_bytes());
        serializer.serialize_str(&hex_str)
    }
}

impl SerializeForVersion for BlockHash<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        self.0.serialize(serializer)
    }
}

impl SerializeForVersion for Address<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        self.0.serialize(serializer)
    }
}

impl SerializeForVersion for TxnHash<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        self.0.serialize(serializer)
    }
}

impl SerializeForVersion for ChainId<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let hex_str = hex_str::bytes_to_hex_str_stripped(self.0 .0.as_be_bytes());
        serializer.serialize_str(&hex_str)
    }
}

impl SerializeForVersion for EthAddress<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let hex_str = hex_str::bytes_to_hex_str_full(self.0 .0.as_bytes());
        serializer.serialize_str(&hex_str)
    }
}

impl SerializeForVersion for StorageKey<'_> {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_str(&self.0 .0.to_hex_str())
    }
}

impl SerializeForVersion for BlockNumber {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_u64(self.0.get())
    }
}

impl SerializeForVersion for U64 {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let hex = pathfinder_serde::bytes_to_hex_str(&self.0.to_be_bytes());
        serializer.serialize_str(&hex)
    }
}

impl SerializeForVersion for U128 {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        let hex = pathfinder_serde::bytes_to_hex_str(&self.0.to_be_bytes());
        serializer.serialize_str(&hex)
    }
}

#[cfg(test)]
mod tests {
    use crate::dto::serialize::Serializer;

    use super::*;

    use pathfinder_common::macro_prelude::*;
    use pretty_assertions_sorted::assert_eq;
    use serde_json::json;

    #[test]
    fn sync_status() {
        use crate::v02::types::syncing::NumberedBlock;
        let status = crate::v02::types::syncing::Status {
            starting: NumberedBlock {
                number: pathfinder_common::BlockNumber::GENESIS,
                hash: block_hash!("0x123"),
            },
            current: NumberedBlock {
                number: pathfinder_common::BlockNumber::GENESIS + 20,
                hash: block_hash!("0x456"),
            },
            highest: NumberedBlock {
                number: pathfinder_common::BlockNumber::GENESIS + 300,
                hash: block_hash!("0x789"),
            },
        };

        let expected = json!({
           "starting_block_hash": BlockHash(&status.starting.hash).serialize(Default::default()).unwrap(),
           "current_block_hash": BlockHash(&status.current.hash).serialize(Default::default()).unwrap(),
           "highest_block_hash": BlockHash(&status.highest.hash).serialize(Default::default()).unwrap(),
           "starting_block_num": BlockNumber(status.starting.number).serialize(Default::default()).unwrap(),
           "current_block_num": BlockNumber(status.current.number).serialize(Default::default()).unwrap(),
           "highest_block_num": BlockNumber(status.highest.number).serialize(Default::default()).unwrap(),
        });

        let encoded = SyncStatus(&status).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn block_number() {
        let number = pathfinder_common::BlockNumber::new_or_panic(1234);
        let expected = json!(1234);
        let encoded = BlockNumber(number).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn felt() {
        let uut = Felt(&felt!("0x1234"));
        let expected = json!("0x1234");
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn block_hash() {
        let hash = block_hash!("0x1234");
        let expected = Felt(&hash.0).serialize(Default::default()).unwrap();
        let encoded = BlockHash(&hash).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn address() {
        let uut = contract_address!("0x1234");
        let expected = Felt(&uut.0).serialize(Default::default()).unwrap();
        let encoded = Address(&uut).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn txn_hash() {
        let uut = transaction_hash!("0x1234");
        let expected = Felt(&uut.0).serialize(Default::default()).unwrap();
        let encoded = TxnHash(&uut).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn chain_id() {
        let uut = ChainId(&pathfinder_common::ChainId(felt!("0x1234")));
        let expected = json!("0x1234");
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn storage_key() {
        let uut = storage_address!("0x1234");
        let expected = json!("0x1234");
        let encoded = StorageKey(&uut).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn eth_address() {
        let uut = pathfinder_common::EthereumAddress(primitive_types::H160::from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7,
        ]));
        let uut = EthAddress(&uut);
        let expected = json!("0x0000000000000000000000000001020304050607");
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn u64() {
        let uut = U64(0x1234);
        let expected = json!("0x1234");
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn u128() {
        let uut = U128(0x1234);
        let expected = json!("0x1234");
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }
}
