use crate::dto::serialize;

use super::serialize::SerializeForVersion;

pub struct Felt<'a>(pub &'a pathfinder_crypto::Felt);
pub struct BlockHash<'a>(pub &'a pathfinder_common::BlockHash);

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
        let encoded = BlockHash(&hash).serialize(Serializer::default()).unwrap();

        assert_eq!(encoded, expected);
    }
}
