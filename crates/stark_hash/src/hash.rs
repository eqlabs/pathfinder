use std::borrow::Cow;
use std::error::Error;
use std::fmt::Display;

use stark_curve::{AffinePoint, FieldElement, FieldElementRepr, ProjectivePoint, PEDERSEN_P0};

use bitvec::{field::BitField, order::Msb0, slice::BitSlice, view::BitView};
use ff::PrimeField;

include!(concat!(env!("OUT_DIR"), "/curve_consts.rs"));

/// The Starknet elliptic curve Field Element.
///
/// Forms the basic building block of most Starknet interactions.
#[derive(Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct StarkHash([u8; 32]);

impl std::fmt::Debug for StarkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StarkHash({})", self)
    }
}

impl std::fmt::Display for StarkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 0xABCDEF1234567890
        write!(f, "0x{:X}", self)
    }
}

impl std::fmt::LowerHex for StarkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{:02x}", b))
    }
}

impl std::fmt::UpperHex for StarkHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{:02X}", b))
    }
}

impl std::default::Default for StarkHash {
    fn default() -> Self {
        StarkHash::ZERO
    }
}

/// Error returned by [StarkHash::from_be_bytes] indicating that
/// the maximum field value was exceeded.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct OverflowError;

impl Error for OverflowError {}

const OVERFLOW_MSG: &str = "The StarkHash maximum value was exceeded.";

impl std::fmt::Display for OverflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(OVERFLOW_MSG)
    }
}

impl StarkHash {
    pub const ZERO: StarkHash = StarkHash([0u8; 32]);

    /// Returns the big-endian representation of this [StarkHash].
    pub fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Big-endian representation of this [StarkHash].
    pub fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convenience function which extends [StarkHash::from_be_bytes] to work with slices.
    pub fn from_be_slice(bytes: &[u8]) -> Result<Self, OverflowError> {
        if bytes.len() > 32 {
            return Err(OverflowError);
        }

        let mut buf = [0u8; 32];
        buf[32 - bytes.len()..].copy_from_slice(bytes);

        StarkHash::from_be_bytes(buf)
    }

    /// Creates a [StarkHash] from big-endian bytes.
    ///
    /// Returns [OverflowError] if not less than the field modulus.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, OverflowError> {
        // FieldElement::from_repr[_vartime] does the check in a correct way
        match FieldElement::from_repr_vartime(FieldElementRepr(bytes)) {
            Some(field_element) => Ok(Self(field_element.to_repr().0)),
            None => Err(OverflowError),
        }
    }

    /// Returns a bit view of the 251 least significant bits in MSB order.
    pub fn view_bits(&self) -> &BitSlice<Msb0, u8> {
        &self.0.view_bits()[5..]
    }

    /// Creates a [StarkHash] from up-to 251 bits.
    pub fn from_bits(bits: &BitSlice<Msb0, u8>) -> Result<Self, OverflowError> {
        if bits.len() > 251 {
            return Err(OverflowError);
        }

        let mut bytes = [0u8; 32];
        bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);

        Ok(Self(bytes))
    }

    /// Returns `true` if the value of [`StarkHash`] is larger than `2^251 - 1`.
    ///
    /// Every [`StarkHash`] that is used to traverse a Merkle-Patricia Tree
    /// must not exceed 251 bits, since 251 is the height of the tree.
    pub fn has_more_than_251_bits(&self) -> bool {
        self.0[0] & 0b1111_1000 > 0
    }
}

impl From<u64> for StarkHash {
    fn from(value: u64) -> Self {
        Self::from_be_slice(&value.to_be_bytes()).expect("64 bits is less than 251 bits")
    }
}

impl From<u128> for StarkHash {
    fn from(value: u128) -> Self {
        Self::from_be_slice(&value.to_be_bytes()).expect("128 bits is less than 251 bits")
    }
}

impl std::ops::Add for StarkHash {
    type Output = StarkHash;

    fn add(self, rhs: Self) -> Self::Output {
        let result = FieldElement::from(self) + FieldElement::from(rhs);
        StarkHash::from(result)
    }
}

/// Computes the [Starknet Pedersen hash] on `a` and `b` using precomputed points.
///
/// [Starknet Pedersen hash]: https://docs.starkware.co/starkex-v3/crypto/pedersen-hash-function
pub fn stark_hash(a: StarkHash, b: StarkHash) -> StarkHash {
    let a = FieldElement::from(a).into_bits();
    let b = FieldElement::from(b).into_bits();

    // Preprocessed material is lookup-tables for each chunk of bits
    let table_size = (1 << CURVE_CONSTS_BITS) - 1;
    let add_points = |acc: &mut ProjectivePoint, bits: &BitSlice<_, u64>, prep: &[AffinePoint]| {
        bits.chunks(CURVE_CONSTS_BITS)
            .enumerate()
            .for_each(|(i, v)| {
                let offset: usize = v.load_le();
                if offset > 0 {
                    // Table lookup at 'offset-1' in table for chunk 'i'
                    acc.add_affine(&prep[i * table_size + offset - 1]);
                }
            });
    };

    // Compute hash
    let mut acc = PEDERSEN_P0;
    add_points(&mut acc, &a[..248], &CURVE_CONSTS_P1); // Add a_low * P1
    add_points(&mut acc, &a[248..252], &CURVE_CONSTS_P2); // Add a_high * P2
    add_points(&mut acc, &b[..248], &CURVE_CONSTS_P3); // Add b_low * P3
    add_points(&mut acc, &b[248..252], &CURVE_CONSTS_P4); // Add b_high * P4

    // Convert to affine
    let result = AffinePoint::from(&acc);

    // Return x-coordinate
    StarkHash::from(result.x)
}

impl From<StarkHash> for FieldElement {
    fn from(hash: StarkHash) -> Self {
        debug_assert_eq!(
            std::mem::size_of::<FieldElement>(),
            std::mem::size_of::<StarkHash>()
        );
        Self::from_repr(FieldElementRepr(hash.to_be_bytes())).unwrap()
    }
}

impl From<FieldElement> for StarkHash {
    fn from(fp: FieldElement) -> Self {
        debug_assert_eq!(
            std::mem::size_of::<FieldElement>(),
            std::mem::size_of::<StarkHash>()
        );
        // unwrap is safe because the FieldElement and StarkHash
        // should both be smaller than the field modulus.
        StarkHash::from_be_bytes(fp.to_repr().0).unwrap()
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub(crate) struct InvalidBufferSizeError {
    expected: usize,
    actual: usize,
}

impl Display for InvalidBufferSizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Expected buffer size {}, got {}",
            self.expected, self.actual,
        ))
    }
}

impl StarkHash {
    /// A convenience function which parses a hex string into a [StarkHash].
    ///
    /// Supports both upper and lower case hex strings, as well as an
    /// optional "0x" prefix.
    pub fn from_hex_str(hex_str: &str) -> Result<Self, HexParseError> {
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
            return Err(HexParseError::InvalidLength {
                max: 64,
                actual: hex_str.len(),
            });
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

    /// The first stage of conversion - skip leading zeros
    fn skip_zeros(&self) -> (impl Iterator<Item = &u8>, usize, usize) {
        // Skip all leading zero bytes
        let it = self.0.iter().skip_while(|&&b| b == 0);
        let num_bytes = it.clone().count();
        let skipped = self.0.len() - num_bytes;
        // The first high nibble can be 0
        let start = if self.0[skipped] < 0x10 { 1 } else { 2 };
        // Number of characters to display
        let len = start + num_bytes * 2;
        (it, start, len)
    }

    /// The second stage of conversion - map bytes to hex str
    fn it_to_hex_str<'a>(
        it: impl Iterator<Item = &'a u8>,
        start: usize,
        len: usize,
        buf: &'a mut [u8],
    ) -> &'a [u8] {
        const LUT: [u8; 16] = *b"0123456789abcdef";
        buf[0] = b'0';
        // Same small lookup table is ~25% faster than hex::encode_from_slice 🤷
        it.enumerate().for_each(|(i, &b)| {
            let idx = b as usize;
            let pos = start + i * 2;
            let x = [LUT[(idx & 0xf0) >> 4], LUT[idx & 0x0f]];
            buf[pos..pos + 2].copy_from_slice(&x);
        });
        buf[1] = b'x';
        &buf[..len]
    }

    /// A convenience function which produces a "0x" prefixed hex str slice in a given buffer `buf`
    /// from a [StarkHash].
    /// Panics if `self.0.len() * 2 + 2 > buf.len()`
    pub fn as_hex_str<'a>(&'a self, buf: &'a mut [u8]) -> &'a str {
        let expected_buf_len = self.0.len() * 2 + 2;
        assert!(
            buf.len() >= expected_buf_len,
            "buffer size is {}, expected at least {}",
            buf.len(),
            expected_buf_len
        );

        if !self.0.iter().any(|b| *b != 0) {
            return "0x0";
        }

        let (it, start, len) = self.skip_zeros();
        let res = Self::it_to_hex_str(it, start, len, buf);
        // Unwrap is safe because `buf` holds valid UTF8 characters.
        std::str::from_utf8(res).unwrap()
    }

    /// A convenience function which produces a "0x" prefixed hex string from a [StarkHash].
    pub fn to_hex_str(&self) -> Cow<'static, str> {
        if !self.0.iter().any(|b| *b != 0) {
            return Cow::from("0x0");
        }
        let (it, start, len) = self.skip_zeros();
        let mut buf = vec![0u8; len];
        Self::it_to_hex_str(it, start, len, &mut buf);
        // Unwrap is safe as the buffer contains valid utf8
        String::from_utf8(buf).unwrap().into()
    }
}

#[derive(Debug, PartialEq)]
pub enum HexParseError {
    InvalidNibble(u8),
    InvalidLength { max: usize, actual: usize },
    Overflow,
}

impl Error for HexParseError {}

impl From<OverflowError> for HexParseError {
    fn from(_: OverflowError) -> Self {
        Self::Overflow
    }
}

impl std::fmt::Display for HexParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidNibble(n) => f.write_fmt(format_args!("Invalid nibble found: 0x{:x}", *n)),
            Self::InvalidLength { max, actual } => {
                f.write_fmt(format_args!("More than {} digits found: {}", *max, *actual))
            }
            Self::Overflow => f.write_str(OVERFLOW_MSG),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::bitvec;
    use pretty_assertions::assert_eq;

    #[test]
    fn view_bits() {
        let one = StarkHash::from_hex_str("1").unwrap();

        let one = one.view_bits().to_bitvec();

        let mut expected = bitvec![0; 251];
        expected.set(250, true);
        assert_eq!(one, expected);
    }

    #[test]
    fn bits_round_trip() {
        let mut bits = bitvec![Msb0, u8; 1; 251];
        bits.set(0, false);
        bits.set(1, false);
        bits.set(2, false);
        bits.set(3, false);
        bits.set(4, false);

        let res = StarkHash::from_bits(&bits).unwrap();

        let x = res.view_bits();
        let y = StarkHash::from_bits(x).unwrap();

        assert_eq!(res, y);
    }

    #[test]
    fn hash() {
        // Test vectors from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/pedersen_hash_test.cc
        let a = "03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb";
        let b = "0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a";
        let expected = "030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662";

        fn parse_hex(str: &str) -> [u8; 32] {
            let mut buf = [0; 32];
            hex::decode_to_slice(str, &mut buf).unwrap();
            buf
        }

        let a = StarkHash::from_be_bytes(parse_hex(a)).unwrap();
        let b = StarkHash::from_be_bytes(parse_hex(b)).unwrap();
        let expected = StarkHash::from_be_bytes(parse_hex(expected)).unwrap();

        let hash = stark_hash(a, b);
        let hash2 = stark_hash(a, b);

        assert_eq!(hash, hash2);
        assert_eq!(hash, expected);
    }

    #[test]
    fn bytes_round_trip() {
        let original = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let hash = StarkHash::from_be_bytes(original).unwrap();
        let bytes = hash.to_be_bytes();
        assert_eq!(bytes, original);
    }

    // Prime field modulus
    const MODULUS: [u8; 32] = [
        8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    #[test]
    fn from_bytes_overflow() {
        // Field modulus
        assert_eq!(StarkHash::from_be_bytes(MODULUS), Err(OverflowError));
        // Field modulus - 1
        let mut max_val = MODULUS;
        max_val[31] -= 1;
        StarkHash::from_be_bytes(max_val).unwrap();
    }

    #[test]
    fn hash_field_round_trip() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let original = StarkHash::from_be_bytes(bytes).unwrap();
        let fp = FieldElement::from(original);
        let hash = StarkHash::from(fp);
        assert_eq!(hash, original);
    }

    mod from_be_slice {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn round_trip() {
            let original = StarkHash::from_hex_str("abcdef0123456789").unwrap();
            let bytes = original.to_be_bytes();
            let result = StarkHash::from_be_slice(&bytes[..]).unwrap();

            assert_eq!(result, original);
        }

        #[test]
        fn too_long() {
            let original = StarkHash::from_hex_str("abcdef0123456789").unwrap();
            let mut bytes = original.to_be_bytes().to_vec();
            bytes.push(0);
            StarkHash::from_be_slice(&bytes[..]).unwrap_err();
        }

        #[test]
        fn short_slice() {
            let original = StarkHash::from_hex_str("abcdef0123456789").unwrap();
            let bytes = original.to_be_bytes();
            let result = StarkHash::from_be_slice(&bytes[24..]);

            assert_eq!(result, Ok(original));
        }

        #[test]
        fn max() {
            let mut max_val = MODULUS;
            max_val[31] -= 1;
            StarkHash::from_be_slice(&max_val[..]).unwrap();
        }

        #[test]
        fn overflow() {
            assert_eq!(StarkHash::from_be_slice(&MODULUS[..]), Err(OverflowError));
        }
    }

    mod fmt {
        use crate::StarkHash;
        use pretty_assertions::assert_eq;

        #[test]
        fn debug() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = StarkHash::from_hex_str(hex_str).unwrap();
            let result = format!("{:?}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);
            let expected = format!("StarkHash({})", starkhash);

            assert_eq!(result, expected);
        }

        #[test]
        fn fmt() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = StarkHash::from_hex_str(hex_str).unwrap();
            let result = format!("{:x}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            // We don't really care which casing is used by fmt.
            assert_eq!(result.to_lowercase(), expected.to_lowercase());
        }

        #[test]
        fn lower_hex() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = StarkHash::from_hex_str(hex_str).unwrap();
            let result = format!("{:x}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            assert_eq!(result, expected.to_lowercase());
        }

        #[test]
        fn upper_hex() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = StarkHash::from_hex_str(hex_str).unwrap();
            let result = format!("{:X}", starkhash);

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            assert_eq!(result, expected.to_uppercase());
        }
    }

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
            assert_matches!(StarkHash::from_hex_str(&"1".repeat(65)).unwrap_err(), HexParseError::InvalidLength{max: 64, actual: n} => assert_eq!(n, 65))
        }

        #[test]
        fn overflow() {
            // Field modulus
            let mut modulus =
                "0x800000000000011000000000000000000000000000000000000000000000001".to_string();
            assert_eq!(
                StarkHash::from_hex_str(&modulus).unwrap_err(),
                HexParseError::Overflow
            );
            // Field modulus - 1
            modulus.pop();
            modulus.push('0');
            StarkHash::from_hex_str(&modulus).unwrap();
        }
    }

    mod to_hex_str {
        use super::*;
        use pretty_assertions::assert_eq;
        const ODD: &str = "0x1234567890abcde";
        const EVEN: &str = "0x1234567890abcdef";
        const MAX: &str = "0x800000000000011000000000000000000000000000000000000000000000000";

        #[test]
        fn zero() {
            assert_eq!(StarkHash::ZERO.to_hex_str(), "0x0");
            let mut buf = [0u8; 66];
            assert_eq!(StarkHash::ZERO.as_hex_str(&mut buf), "0x0");
        }

        #[test]
        fn odd() {
            let hash = StarkHash::from_hex_str(ODD).unwrap();
            assert_eq!(hash.to_hex_str(), ODD);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), ODD);
        }

        #[test]
        fn even() {
            let hash = StarkHash::from_hex_str(EVEN).unwrap();
            assert_eq!(hash.to_hex_str(), EVEN);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), EVEN);
        }

        #[test]
        fn max() {
            let hash = StarkHash::from_hex_str(MAX).unwrap();
            assert_eq!(hash.to_hex_str(), MAX);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), MAX);
        }

        #[test]
        #[should_panic]
        fn buffer_too_small() {
            let mut buf = [0u8; 65];
            StarkHash::ZERO.as_hex_str(&mut buf);
        }
    }

    mod has_more_than_251_bits {
        use super::*;

        #[test]
        fn has_251_bits() {
            let mut bytes = [0xFFu8; 32];
            bytes[0] = 0x07;
            let h = StarkHash::from_be_bytes(bytes).unwrap();
            assert!(!h.has_more_than_251_bits());
        }

        #[test]
        fn has_252_bits() {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x08;
            let h = StarkHash::from_be_bytes(bytes).unwrap();
            assert!(h.has_more_than_251_bits());
        }
    }
}
