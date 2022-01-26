use super::StarkHash;
use serde::{de::Visitor, Deserialize, Serialize};
use std::str::FromStr;

impl Serialize for StarkHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self == &StarkHash::ZERO {
            return serializer.serialize_str("0x0");
        }

        const LUT: [u8; 16] = *b"0123456789abcdef";

        let mut buf = [0u8; 66];
        buf[0] = b'0';
        // Skip all leading zero bytes
        let it = self.0.iter().skip_while(|&&b| b == 0);
        let num_bytes = it.clone().count();
        let skipped = 32 - num_bytes;
        // The first high nibble can be 0
        let start = if self.0[skipped] < 0x10 { 1 } else { 2 };
        let end = start + num_bytes * 2;
        // Same lookup table is ~25% faster than hex::encode_from_slice 🤷
        it.enumerate().for_each(|(i, &b)| {
            let idx = b as usize;
            let pos = start + i * 2;
            let x = [LUT[(idx & 0xf0) >> 4], LUT[idx & 0x0f]];
            buf[pos..pos + 2].copy_from_slice(&x);
        });

        buf[1] = b'x';

        // Unwrap is safe as the buffer contains valid utf8
        serializer.serialize_str(std::str::from_utf8(&buf[..end]).unwrap())
    }
}

impl<'de> Deserialize<'de> for StarkHash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(StarkHashVisitor)
    }
}

struct StarkHashVisitor;

impl<'de> Visitor<'de> for StarkHashVisitor {
    type Value = StarkHash;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a hex string of up to 64 digits with an optional '0x' prefix")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        StarkHash::from_hex_str(v).map_err(|e| serde::de::Error::custom(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    const ZERO: &str = r#""0x0""#;
    const ODD: &str = "0x1234567890abcde";
    const EVEN: &str = "0x1234567890abcdef";
    const MAX: &str = "0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn empty() {
        assert_eq!(
            serde_json::from_str::<StarkHash>(r#""""#).unwrap(),
            StarkHash::ZERO
        );
        assert_eq!(
            serde_json::from_str::<StarkHash>(r#""0x""#).unwrap(),
            StarkHash::ZERO
        );
    }

    #[test]
    fn zero() {
        let original = StarkHash::ZERO;
        assert_eq!(serde_json::to_string(&original).unwrap(), ZERO);
        assert_eq!(serde_json::from_str::<StarkHash>(ZERO).unwrap(), original);
    }

    #[test]
    fn odd() {
        let original = StarkHash::from_hex_str(ODD).unwrap();
        let expected = format!("\"{}\"", ODD);
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<StarkHash>(&expected).unwrap(),
            original
        );
    }

    #[test]
    fn even() {
        let original = StarkHash::from_hex_str(EVEN).unwrap();
        let expected = format!("\"{}\"", EVEN);
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<StarkHash>(&expected).unwrap(),
            original
        );
    }

    #[test]
    fn max() {
        let original = StarkHash::from_hex_str(MAX).unwrap();
        let expected = format!("\"{}\"", MAX);
        assert_eq!(serde_json::to_string(&original).unwrap(), expected);
        assert_eq!(
            serde_json::from_str::<StarkHash>(&expected).unwrap(),
            original
        );
    }
}
