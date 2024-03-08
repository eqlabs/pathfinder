use crate::dto::serialize;

use super::serialize::SerializeForVersion;

pub struct SyncStatus<'a>(pub &'a crate::v02::types::syncing::Status);

pub struct Felt<'a>(pub &'a pathfinder_crypto::Felt);
pub struct BlockHash<'a>(pub &'a pathfinder_common::BlockHash);
pub struct ChainId<'a>(pub &'a pathfinder_common::ChainId);
pub struct BlockNumber(pub pathfinder_common::BlockNumber);

mod hex_str {
    use std::borrow::Cow;

    const LUT: [u8; 16] = *b"0123456789abcdef";

    pub fn bytes_to_hex_str_stripped(data: &[u8]) -> Cow<'static, str> {
        // Skip empty bytes
        let zero_count = data.iter().take_while(|b| **b == 0).count();
        let data = &data[zero_count..];

        if data.is_empty() {
            return Cow::from("0x0");
        }

        // Is the most significant nibble zero? We need to skip it if it is.
        // Index is safe since we just checked that it is non-empty.
        let zero_nibble = (0xF0 & data[0]) == 0;
        to_hex_str(data, zero_nibble).into()
    }

    pub fn bytes_to_hex_str_full(data: &[u8]) -> String {
        to_hex_str(data, false)
    }

    #[inline]
    fn to_hex_str(data: &[u8], skip_first_nibble: bool) -> String {
        let count = if skip_first_nibble {
            data.len() * 2 - 1
        } else {
            data.len() * 2
        };
        let mut buf = vec![0; 2 + count];
        buf[0] = b'0';
        buf[1] = b'x';

        // Handle the first byte separately as we may need to skip the first nibble.
        let (offset, data) = if skip_first_nibble {
            buf[2] = LUT[data[0] as usize & 0x0f];
            (3, &data[1..])
        } else {
            (2, data)
        };

        // Same small lookup table is ~25% faster than hex::encode_from_slice 🤷
        for (i, b) in data.iter().enumerate() {
            let idx = *b as usize;
            let pos = offset + i * 2;
            buf[pos] = LUT[(idx & 0xf0) >> 4];
            buf[pos + 1] = LUT[idx & 0x0f];
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
        serializer.serialize(&Felt(&self.0 .0))
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

impl SerializeForVersion for BlockNumber {
    fn serialize(
        &self,
        serializer: serialize::Serializer,
    ) -> Result<serialize::Ok, serialize::Error> {
        serializer.serialize_u64(self.0.get())
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
    fn block_number() {
        let number = pathfinder_common::BlockNumber::new_or_panic(1234);
        let expected = json!(1234);
        let encoded = BlockNumber(number).serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

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

        let s = Serializer::default();

        let expected = json!({
           "starting_block_hash": BlockHash(&status.starting.hash).serialize(s).unwrap(),
           "current_block_hash": BlockHash(&status.current.hash).serialize(s).unwrap(),
           "highest_block_hash": BlockHash(&status.highest.hash).serialize(s).unwrap(),
           "starting_block_num": BlockNumber(status.starting.number).serialize(s).unwrap(),
           "current_block_num": BlockNumber(status.current.number).serialize(s).unwrap(),
           "highest_block_num": BlockNumber(status.highest.number).serialize(s).unwrap(),
        });

        let encoded = SyncStatus(&status).serialize(s).unwrap();

        assert_eq!(encoded, expected);
    }

    #[test]
    fn chain_id() {
        let uut = ChainId(&pathfinder_common::ChainId(felt!("0x1234")));
        let expected = json!("0x1234");
        let encoded = uut.serialize(Default::default()).unwrap();

        assert_eq!(encoded, expected);
    }

    mod hex_str {
        use super::super::hex_str::*;

        #[test]
        fn zero() {
            let data = 0x0u16.to_be_bytes();
            assert_eq!(&bytes_to_hex_str_full(&data), "0x0000");
            assert_eq!(&bytes_to_hex_str_stripped(&data), "0x0");
        }

        #[test]
        fn leading_zeros_even() {
            let data = 0x12u16.to_be_bytes();
            assert_eq!(&bytes_to_hex_str_full(&data), "0x0012");
            assert_eq!(&bytes_to_hex_str_stripped(&data), "0x12");
        }

        #[test]
        fn leading_zeros_odd() {
            let data = 0x1u16.to_be_bytes();
            assert_eq!(&bytes_to_hex_str_full(&data), "0x0001");
            assert_eq!(&bytes_to_hex_str_stripped(&data), "0x1");
        }

        #[test]
        fn multibyte_odd() {
            let data = 0x12345u32.to_be_bytes();
            assert_eq!(&bytes_to_hex_str_full(&data), "0x00012345");
            assert_eq!(&bytes_to_hex_str_stripped(&data), "0x12345");
        }

        #[test]
        fn multibyte_even() {
            let data = 0x123456u32.to_be_bytes();
            assert_eq!(&bytes_to_hex_str_full(&data), "0x00123456");
            assert_eq!(&bytes_to_hex_str_stripped(&data), "0x123456");
        }
    }
}
