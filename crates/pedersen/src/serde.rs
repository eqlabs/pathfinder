use super::{OverflowError, StarkHash, OVERFLOW_MSG};
use serde::{de::Visitor, Deserialize, Serialize};

impl StarkHash {
    /// A convenience function which parses a hex string into a [StarkHash].
    ///
    /// Supports both upper and lower case hex strings, as well as an
    /// optional "0x" prefix.
    pub fn from_hex_str(hex_str: &str) -> Result<StarkHash, HexParseError> {
        fn parse_hex_digit(digit: u8) -> Result<u8, HexParseError> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'A'..=b'F' => Ok(digit - b'A' + 10),
                b'a'..=b'f' => Ok(digit - b'a' + 10),
                other => Err(HexParseError::InvalidNibble(other)),
            }
        }

        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        if hex_str.len() > 64 {
            return Err(HexParseError::InvalidLength(hex_str.len()));
        }

        let mut buf = [0u8; 32];

        // We want the result in big-endian so reverse iterate over each pair of nibbles.
        let chunks = hex_str.as_bytes().rchunks_exact(2);

        // Handle a possible odd nibble remaining nibble.
        let odd_nibble = chunks.remainder();
        if !odd_nibble.is_empty() {
            let full_bytes = hex_str.len() / 2;
            buf[31 - full_bytes] = parse_hex_digit(odd_nibble[0])?;
        }

        for (i, c) in chunks.enumerate() {
            // Indexing c[0] and c[1] are safe since chunk-size is 2.
            buf[31 - i] = parse_hex_digit(c[0])? << 4 | parse_hex_digit(c[1])?;
        }

        let hash = StarkHash::from_be_bytes(buf)?;
        Ok(hash)
    }
}

#[derive(Debug, PartialEq)]
pub enum HexParseError {
    InvalidNibble(u8),
    InvalidLength(usize),
    Overflow,
}

impl From<OverflowError> for HexParseError {
    fn from(_: OverflowError) -> Self {
        Self::Overflow
    }
}

impl std::fmt::Display for HexParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNibble(n) => f.write_fmt(format_args!("Invalid nibble found: 0x{:x}", *n)),
            Self::InvalidLength(n) => {
                f.write_fmt(format_args!("More than 64 digits found: {}", *n))
            }
            Self::Overflow => f.write_str(OVERFLOW_MSG),
        }
    }
}

impl Serialize for StarkHash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self == &StarkHash::zero() {
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

    mod from_hex_str {
        use super::*;
        use assert_matches::assert_matches;
        use pretty_assertions::assert_eq;

        /// Test hex string with its expected [StarkHash].
        fn test_data() -> (&'static str, StarkHash) {
            let mut expected = [0; 32];
            expected[31] = 0xEF;
            expected[30] = 0xCD;
            expected[29] = 0xAB;
            expected[28] = 0xef;
            expected[27] = 0xcd;
            expected[26] = 0xab;
            expected[25] = 0x89;
            expected[24] = 0x67;
            expected[23] = 0x45;
            expected[22] = 0x23;
            expected[21] = 0x01;
            let expected = StarkHash::from_be_bytes(expected).unwrap();

            ("0123456789abcdefABCDEF", expected)
        }

        #[test]
        fn simple() {
            let (test_str, expected) = test_data();
            let uut = StarkHash::from_hex_str(test_str).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn prefix() {
            let (test_str, expected) = test_data();
            let uut = StarkHash::from_hex_str(&format!("0x{}", test_str)).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn leading_zeros() {
            let (test_str, expected) = test_data();
            let uut = StarkHash::from_hex_str(&format!("000000000{}", test_str)).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn prefix_and_leading_zeros() {
            let (test_str, expected) = test_data();
            let uut = StarkHash::from_hex_str(&format!("0x000000000{}", test_str)).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn invalid_nibble() {
            assert_matches!(StarkHash::from_hex_str("0x123z").unwrap_err(), HexParseError::InvalidNibble(n) => assert_eq!(n, b'z'))
        }

        #[test]
        fn invalid_len() {
            assert_matches!(StarkHash::from_hex_str(&"1".repeat(65)).unwrap_err(), HexParseError::InvalidLength(n) => assert_eq!(n, 65))
        }

        #[test]
        fn overflow() {
            let bit_252th_set = "8".to_string() + &"0".repeat(63);
            assert_eq!(
                StarkHash::from_hex_str(&bit_252th_set).unwrap_err(),
                HexParseError::Overflow
            )
        }
    }

    mod serde {
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
                StarkHash::zero()
            );
            assert_eq!(
                serde_json::from_str::<StarkHash>(r#""0x""#).unwrap(),
                StarkHash::zero()
            );
        }

        #[test]
        fn zero() {
            let original = StarkHash::zero();
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
}
