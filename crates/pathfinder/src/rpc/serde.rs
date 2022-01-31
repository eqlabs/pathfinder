//! Utilities used for serializing/deserializing sequencer REST API related data.

use crate::core::{
    CallParam, CallSignatureElem, ConstructorParam, EthereumAddress, EventData, EventKey,
    L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem, TransactionSignatureElem,
};
use bigdecimal::BigDecimal;
use num_bigint::{BigInt, BigUint, Sign};
use pedersen::{FromSliceError, HexParseError, StarkHash};
use serde_with::serde_conv;
use std::str::FromStr;
use web3::types::H160;

serde_conv!(
    pub CallParamAsDecimalStr,
    CallParam,
    |serialize_me: &CallParam| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(CallParam)
);

serde_conv!(
    pub CallSignatureElemAsDecimalStr,
    CallSignatureElem,
    |serialize_me: &CallSignatureElem| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(CallSignatureElem)
);

serde_conv!(
    pub ConstructorParamAsDecimalStr,
    ConstructorParam,
    |serialize_me: &ConstructorParam| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(ConstructorParam)
);

serde_conv!(
    pub EventDataAsDecimalStr,
    EventData,
    |serialize_me: &EventData| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(EventData)
);

serde_conv!(
    pub EventKeyAsDecimalStr,
    EventKey,
    |serialize_me: &EventKey| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(EventKey)
);

serde_conv!(
    pub L1ToL2MessagePayloadElemAsDecimalStr,
    L1ToL2MessagePayloadElem,
    |serialize_me: &L1ToL2MessagePayloadElem| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(L1ToL2MessagePayloadElem)
);

serde_conv!(
    pub L2ToL1MessagePayloadElemAsDecimalStr,
    L2ToL1MessagePayloadElem,
    |serialize_me: &L2ToL1MessagePayloadElem| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(L2ToL1MessagePayloadElem)
);

serde_conv!(
    pub TransactionSignatureElemAsDecimalStr,
    TransactionSignatureElem,
    |serialize_me: &TransactionSignatureElem| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(TransactionSignatureElem)
);

serde_with::serde_conv!(
    pub EthereumAddressAsHexStr,
    EthereumAddress,
    |serialize_me: &EthereumAddress| bytes_to_hex_str(serialize_me.0.as_bytes()),
    |s: &str| bytes_from_hex_str::<{ H160::len_bytes() }>(s).map(|b| EthereumAddress(H160::from(b)))
);

/// A helper conversion function. Only use with __sequencer API related types__.
fn starkhash_from_biguint(b: BigUint) -> Result<StarkHash, FromSliceError> {
    let mut b = b.to_bytes_be();
    let len = b.len();

    if len > 32 {
        return Err(FromSliceError::BadLength);
    }

    if len < 32 {
        b.resize(32, 0);
        b.as_mut_slice().copy_within(..len, 32 - len);
        b[..32 - len].fill(0);
    }

    StarkHash::from_be_slice(&b[..])
}

/// A helper conversion function. Only use with __sequencer API related types__.
pub fn starkhash_to_dec_str(h: &StarkHash) -> String {
    let b = h.to_be_bytes();
    let b = BigInt::from_bytes_be(Sign::Plus, &b);
    let b = BigDecimal::from(b);
    b.to_string()
}

/// A helper conversion function. Only use with __sequencer API related types__.
fn starkhash_from_dec_str(s: &str) -> Result<StarkHash, anyhow::Error> {
    let b = BigUint::from_str(s)?;
    let h = starkhash_from_biguint(b)?;
    Ok(h)
}

/// A convenience function which parses a hex string into a byte array.
///
/// Supports both upper and lower case hex strings, as well as an
/// optional "0x" prefix.
fn bytes_from_hex_str<const N: usize>(hex_str: &str) -> Result<[u8; N], HexParseError> {
    fn parse_hex_digit(digit: u8) -> Result<u8, HexParseError> {
        match digit {
            b'0'..=b'9' => Ok(digit - b'0'),
            b'A'..=b'F' => Ok(digit - b'A' + 10),
            b'a'..=b'f' => Ok(digit - b'a' + 10),
            other => Err(HexParseError::InvalidNibble(other)),
        }
    }

    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex_str.len() > N * 2 {
        return Err(HexParseError::InvalidLength(hex_str.len()));
    }

    let mut buf = [0u8; N];

    // We want the result in big-endian so reverse iterate over each pair of nibbles.
    let chunks = hex_str.as_bytes().rchunks_exact(2);

    // Handle a possible odd nibble remaining nibble.
    let odd_nibble = chunks.remainder();
    if !odd_nibble.is_empty() {
        let full_bytes = hex_str.len() / 2;
        buf[N - 1 - full_bytes] = parse_hex_digit(odd_nibble[0])?;
    }

    for (i, c) in chunks.enumerate() {
        // Indexing c[0] and c[1] are safe since chunk-size is 2.
        buf[N - 1 - i] = parse_hex_digit(c[0])? << 4 | parse_hex_digit(c[1])?;
    }

    Ok(buf)
}

/// A convenience function which produces a "0x" prefixed hex string from a byte slice.
fn bytes_to_hex_str(bytes: &[u8]) -> String {
    if !bytes.iter().any(|b| *b != 0) {
        return "0x0".to_string();
    }

    const LUT: [u8; 16] = *b"0123456789abcdef";

    // Skip all leading zero bytes
    let it = bytes.iter().skip_while(|&&b| b == 0);
    let num_bytes = it.clone().count();
    let skipped = bytes.len() - num_bytes;
    // The first high nibble can be 0
    let start = if bytes[skipped] < 0x10 { 1 } else { 2 };
    let len = start + num_bytes * 2;
    let mut buf = vec![0; len];
    buf[0] = b'0';
    // Same small lookup table is ~25% faster than hex::encode_from_slice 🤷
    it.enumerate().for_each(|(i, &b)| {
        let idx = b as usize;
        let pos = start + i * 2;
        let x = [LUT[(idx & 0xf0) >> 4], LUT[idx & 0x0f]];
        buf[pos..pos + 2].copy_from_slice(&x);
    });
    buf[1] = b'x';

    // Unwrap is safe as the buffer contains valid utf8
    String::from_utf8(buf).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    const ZERO: (&str, &str, [u8; 1]) = ("0x0", "0", [0]);
    const ODD: (&str, &str, [u8; 8]) = (
        "0x1234567890abcde",
        "81985529205931230",
        [1, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde],
    );
    const EVEN: (&str, &str, [u8; 8]) = (
        "0x1234567890abcdef",
        "1311768467294899695",
        [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
    );
    const MAX: (&str, &str, [u8; 32]) = (
        "0x800000000000011000000000000000000000000000000000000000000000000",
        "3618502788666131213697322783095070105623107215331596699973092056135872020480",
        [
            8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
    );
    const OVERFLOW: (&str, &str, [u8; 32]) = (
        "0x800000000000011000000000000000000000000000000000000000000000001",
        "3618502788666131213697322783095070105623107215331596699973092056135872020481",
        [
            8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1,
        ],
    );
    const TOO_LONG: (&str, &str, [u8; 33]) = (
        "0x80000000000001100000000000000000000000000000000000000000000000100",
        "926336713898529590706514632472337947039515447124888755193111566370783237243136",
        [
            8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0,
        ],
    );
    const INVALID_DIGIT: (&str, &str) = ("0x123z", "123a");

    #[test]
    fn zero() {
        let a = starkhash_from_biguint(BigUint::from_bytes_be(&ZERO.2)).unwrap();
        let b = starkhash_from_dec_str(ZERO.1).unwrap();
        let expected = StarkHash::ZERO;
        assert_eq!(expected, a);
        assert_eq!(expected, b);
        assert_eq!(starkhash_to_dec_str(&expected), ZERO.1);

        let c: [u8; 32] = bytes_from_hex_str(ZERO.0).unwrap();
        assert!(c.iter().all(|x| *x == 0));
        assert_eq!(bytes_to_hex_str(&c[..]), ZERO.0);
    }

    #[test]
    fn odd() {
        let a = starkhash_from_biguint(BigUint::from_bytes_be(&ODD.2)).unwrap();
        let b = starkhash_from_dec_str(ODD.1).unwrap();
        let expected = StarkHash::from_hex_str(ODD.0).unwrap();
        assert_eq!(expected, a);
        assert_eq!(expected, b);
        assert_eq!(starkhash_to_dec_str(&expected), ODD.1);

        let c: [u8; 8] = bytes_from_hex_str(ODD.0).unwrap();
        assert_eq!(c, ODD.2);
        assert_eq!(bytes_to_hex_str(&c[..]), ODD.0);
    }

    #[test]
    fn even() {
        let a = starkhash_from_biguint(BigUint::from_bytes_be(&EVEN.2)).unwrap();
        let b = starkhash_from_dec_str(EVEN.1).unwrap();
        let expected = StarkHash::from_hex_str(EVEN.0).unwrap();
        assert_eq!(expected, a);
        assert_eq!(expected, b);
        assert_eq!(starkhash_to_dec_str(&expected), EVEN.1);

        let c: [u8; 8] = bytes_from_hex_str(EVEN.0).unwrap();
        assert_eq!(c, EVEN.2);
        assert_eq!(bytes_to_hex_str(&c[..]), EVEN.0);
    }

    #[test]
    fn max() {
        let a = starkhash_from_biguint(BigUint::from_bytes_be(&MAX.2)).unwrap();
        let b = starkhash_from_dec_str(MAX.1).unwrap();
        let expected = StarkHash::from_hex_str(MAX.0).unwrap();
        assert_eq!(expected, a);
        assert_eq!(expected, b);
        assert_eq!(starkhash_to_dec_str(&expected), MAX.1);

        let c: [u8; 32] = bytes_from_hex_str(MAX.0).unwrap();
        assert_eq!(c, MAX.2);
        assert_eq!(bytes_to_hex_str(&c[..]), MAX.0);
    }

    #[test]
    fn overflow() {
        use pedersen::FromSliceError;
        assert_eq!(
            starkhash_from_biguint(BigUint::from_bytes_be(&OVERFLOW.2)),
            Err(FromSliceError::Overflow)
        );
        assert_eq!(
            starkhash_from_dec_str(OVERFLOW.1)
                .unwrap_err()
                .downcast::<FromSliceError>()
                .unwrap(),
            FromSliceError::Overflow
        );
    }

    #[test]
    fn too_long() {
        use pedersen::{FromSliceError, HexParseError};
        assert_eq!(
            starkhash_from_biguint(BigUint::from_bytes_be(&TOO_LONG.2)),
            Err(FromSliceError::BadLength)
        );
        assert_eq!(
            starkhash_from_dec_str(TOO_LONG.1)
                .unwrap_err()
                .downcast::<FromSliceError>()
                .unwrap(),
            FromSliceError::BadLength
        );
        assert_eq!(
            bytes_from_hex_str::<32>(TOO_LONG.0),
            Err(HexParseError::InvalidLength(65))
        );
    }

    #[test]
    fn invalid_digit() {
        use num_bigint::ParseBigIntError;
        starkhash_from_dec_str(INVALID_DIGIT.1)
            .unwrap_err()
            .downcast::<ParseBigIntError>()
            .unwrap();
        assert_eq!(
            bytes_from_hex_str::<32>(INVALID_DIGIT.0),
            Err(HexParseError::InvalidNibble(b'z'))
        );
    }
}
