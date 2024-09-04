use std::borrow::Cow;
use std::error::Error;

use bitvec::order::Msb0;
use bitvec::slice::BitSlice;
use bitvec::view::BitView;
use fake::Dummy;

use crate::algebra::field::montfelt::MontFelt;

/// Starknet Field Element.
///
/// A field element is a number 0..p-1 with p=2^{251}+17*2^{192}+1, and it forms
/// the basic building block of most Starknet interactions.
#[derive(Clone, Copy, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct Felt([u8; 32]);

const MODULUS_U64: [u64; 4] = [576460752303423505u64, 0, 0, 1];

impl std::fmt::Debug for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Felt({self})")
    }
}

impl std::fmt::Display for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 0xABCDEF1234567890
        write!(f, "0x{self:X}")
    }
}

impl std::fmt::LowerHex for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{b:02x}"))
    }
}

impl std::fmt::UpperHex for Felt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|&b| write!(f, "{b:02X}"))
    }
}

impl Default for Felt {
    fn default() -> Self {
        Felt::ZERO
    }
}

impl<T> Dummy<T> for Felt {
    fn dummy_with_rng<R: rand::Rng + ?Sized>(_: &T, rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        // Some 252 bit values are fine too but we don't really care here
        bytes[0] &= 0x03;
        Self(bytes)
    }
}

/// Error returned by [Felt::from_be_bytes] indicating the maximum field value
/// was exceeded.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct OverflowError;

impl Error for OverflowError {}

const OVERFLOW_MSG: &str = "The maximum field value was exceeded.";

impl std::fmt::Display for OverflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(OVERFLOW_MSG)
    }
}

impl Felt {
    pub const ZERO: Felt = Felt([0u8; 32]);
    pub const ONE: Felt = Self::from_u64(1);

    /// Return true if the element is zero.
    pub fn is_zero(&self) -> bool {
        self == &Felt::ZERO
    }

    /// Returns the big-endian representation of this [Felt].
    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Returns the little-endian representation of this [Felt].
    pub fn to_le_bytes(self) -> [u8; 32] {
        let mut tmp = self.0;
        tmp.reverse();
        tmp
    }

    /// Big-endian representation of this [Felt].
    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Big-endian mutable representation of this [Felt].
    pub fn as_mut_be_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    /// Convenience function which extends [Felt::from_be_bytes] to work with
    /// slices.
    pub const fn from_be_slice(bytes: &[u8]) -> Result<Self, OverflowError> {
        if bytes.len() > 32 {
            return Err(OverflowError);
        }

        let mut buf = [0u8; 32];
        let mut index = 0;
        loop {
            if index == bytes.len() {
                break;
            }
            buf[32 - bytes.len() + index] = bytes[index];
            index += 1;
        }

        Felt::from_be_bytes(buf)
    }

    pub fn random<R: rand::Rng>(rng: &mut R) -> Self {
        let r = MontFelt::random(rng);
        Felt::from(r)
    }

    /// Creates a [Felt] from big-endian bytes.
    ///
    /// Returns [OverflowError] if not less than the field modulus.
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Result<Self, OverflowError> {
        #[rustfmt::skip]
        let limbs = [
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
                bytes[4], bytes[5], bytes[6], bytes[7],
            ]),
            u64::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11],
                bytes[12], bytes[13], bytes[14], bytes[15],
            ]),
            u64::from_be_bytes([
                bytes[16], bytes[17], bytes[18], bytes[19],
                bytes[20], bytes[21], bytes[22], bytes[23],
            ]),
            u64::from_be_bytes([
                bytes[24], bytes[25], bytes[26], bytes[27],
                bytes[28], bytes[29], bytes[30], bytes[31],
            ]),
        ];

        // Loop over each word, if all previous are equal and current is less, we are
        // good.
        let mut maybe_overflow = true;
        let mut i = 0;
        while i < 4 && maybe_overflow {
            if limbs[i] < MODULUS_U64[i] {
                maybe_overflow = false;
            } else if limbs[i] > MODULUS_U64[i] {
                return Err(OverflowError);
            }
            i += 1;
        }
        if maybe_overflow {
            Err(OverflowError)
        } else {
            Ok(Felt(bytes))
        }
    }

    /// Returns a bit view of the 251 least significant bits in MSB order.
    pub fn view_bits(&self) -> &BitSlice<u8, Msb0> {
        &self.0.view_bits()[5..]
    }

    /// Creates a [Felt] from up-to 251 bits.
    pub fn from_bits(bits: &BitSlice<u8, Msb0>) -> Result<Self, OverflowError> {
        if bits.len() > 251 {
            return Err(OverflowError);
        }

        let mut bytes = [0u8; 32];
        bytes.view_bits_mut::<Msb0>()[256 - bits.len()..].copy_from_bitslice(bits);

        Ok(Self(bytes))
    }

    /// Returns `true` if the value of [`Felt`] is larger than `2^251 - 1`.
    ///
    /// Every [`Felt`] that is used to traverse a Merkle-Patricia Tree
    /// must not exceed 251 bits, since 251 is the height of the tree.
    pub const fn has_more_than_251_bits(&self) -> bool {
        self.0[0] & 0b1111_1000 > 0
    }

    pub const fn from_u64(u: u64) -> Self {
        const_expect!(
            Self::from_be_slice(&u.to_be_bytes()),
            "64 bits is less than 251 bits"
        )
    }

    pub const fn from_u128(u: u128) -> Self {
        const_expect!(
            Self::from_be_slice(&u.to_be_bytes()),
            "128 bits is less than 251 bits"
        )
    }
}

macro_rules! const_expect {
    ($e:expr, $why:expr) => {{
        match $e {
            Ok(x) => x,
            Err(_) => panic!(concat!("Expectation failed: ", $why)),
        }
    }};
}

use const_expect;

use crate::algebra::field::CurveOrderMontFelt;

impl From<u64> for Felt {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u128> for Felt {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl From<[u8; 32]> for Felt {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryInto<u128> for Felt {
    type Error = OverflowError;

    fn try_into(self) -> Result<u128, Self::Error> {
        let initial_zeroes = self.0.iter().take_while(|b| **b == 0).count();
        const EXPECTED_ZEROES: usize = (32 - u128::BITS / u8::BITS) as usize;

        if initial_zeroes < EXPECTED_ZEROES {
            return Err(OverflowError);
        }

        let bytes = self.0[EXPECTED_ZEROES..]
            .try_into()
            .expect("Should match u128 size");
        Ok(u128::from_be_bytes(bytes))
    }
}

impl TryInto<u64> for Felt {
    type Error = OverflowError;

    fn try_into(self) -> Result<u64, Self::Error> {
        let initial_zeroes = self.0.iter().take_while(|b| **b == 0).count();
        const EXPECTED_ZEROES: usize = (32 - u64::BITS / u8::BITS) as usize;

        if initial_zeroes < EXPECTED_ZEROES {
            return Err(OverflowError);
        }
        let bytes = self.0[EXPECTED_ZEROES..]
            .try_into()
            .expect("Should match u64 size");
        Ok(u64::from_be_bytes(bytes))
    }
}

impl std::ops::Add for Felt {
    type Output = Felt;

    fn add(self, rhs: Self) -> Self::Output {
        let result = MontFelt::from(self) + MontFelt::from(rhs);
        Felt::from(result)
    }
}

impl std::ops::Sub for Felt {
    type Output = Felt;

    fn sub(self, rhs: Self) -> Self::Output {
        let result = MontFelt::from(self) - MontFelt::from(rhs);
        Felt::from(result)
    }
}

impl From<MontFelt> for Felt {
    fn from(fp: MontFelt) -> Self {
        // safe as BE-bytes representations are the same
        debug_assert_eq!(std::mem::size_of::<MontFelt>(), std::mem::size_of::<Felt>());
        let bytes: [u8; 32] = fp.to_be_bytes();
        Felt::from_be_bytes(bytes).unwrap()
    }
}

impl From<CurveOrderMontFelt> for Felt {
    fn from(value: CurveOrderMontFelt) -> Self {
        // safe as BE-bytes representations are the same
        debug_assert_eq!(std::mem::size_of::<MontFelt>(), std::mem::size_of::<Felt>());
        let bytes = value.to_be_bytes();
        Felt::from_be_bytes(bytes).unwrap()
    }
}

impl Felt {
    /// A convenience function which parses a hex string into a [Felt].
    ///
    /// Supports both upper and lower case hex strings, as well as an optional
    /// "0x" prefix.
    pub const fn from_hex_str(hex_str: &str) -> Result<Self, HexParseError> {
        const fn parse_hex_digit(digit: u8) -> Result<u8, HexParseError> {
            match digit {
                b'0'..=b'9' => Ok(digit - b'0'),
                b'A'..=b'F' => Ok(digit - b'A' + 10),
                b'a'..=b'f' => Ok(digit - b'a' + 10),
                other => Err(HexParseError::InvalidNibble(other)),
            }
        }

        let bytes = hex_str.as_bytes();
        let start = if bytes.len() >= 2 && bytes[0] == b'0' && bytes[1] == b'x' {
            2
        } else {
            0
        };
        let len = bytes.len() - start;

        if len > 64 {
            return Err(HexParseError::InvalidLength {
                max: 64,
                actual: bytes.len(),
            });
        }

        let mut buf = [0u8; 32];

        // We want the result in big-endian so reverse iterate over each pair of
        // nibbles. let chunks = hex_str.as_bytes().rchunks_exact(2);

        // Handle a possible odd nibble remaining nibble.
        if len % 2 == 1 {
            let idx = len / 2;
            buf[31 - idx] = match parse_hex_digit(bytes[start]) {
                Ok(b) => b,
                Err(e) => return Err(e),
            };
        }

        let chunks = len / 2;
        let mut chunk = 0;

        while chunk < chunks {
            let lower = match parse_hex_digit(bytes[bytes.len() - chunk * 2 - 1]) {
                Ok(b) => b,
                Err(e) => return Err(e),
            };
            let upper = match parse_hex_digit(bytes[bytes.len() - chunk * 2 - 2]) {
                Ok(b) => b,
                Err(e) => return Err(e),
            };
            buf[31 - chunk] = upper << 4 | lower;
            chunk += 1;
        }

        let felt = match Felt::from_be_bytes(buf) {
            Ok(felt) => felt,
            Err(OverflowError) => return Err(HexParseError::Overflow),
        };
        Ok(felt)
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

    /// A convenience function which produces a "0x" prefixed hex str slice in a
    /// given buffer `buf` from a [Felt].
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

    /// A convenience function which produces a "0x" prefixed hex string from a
    /// [Felt].
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

/// Error returned by [Felt::from_hex_str] indicating an invalid hex string.
#[derive(Debug, PartialEq, Eq)]
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
    use bitvec::bitvec;
    use pretty_assertions_sorted::assert_eq;

    use super::*;

    const MODULUS_U8: [u8; 32] = [
        8, 0, 0, 0, 0, 0, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ];

    #[test]
    fn view_bits() {
        let one = Felt::from_hex_str("1").unwrap();

        let one = one.view_bits().to_bitvec();

        let mut expected = bitvec![0; 251];
        expected.set(250, true);
        assert_eq!(one, expected);
    }

    #[test]
    fn bits_round_trip() {
        let mut bits = bitvec![u8, Msb0; 1; 251];
        bits.set(0, false);
        bits.set(1, false);
        bits.set(2, false);
        bits.set(3, false);
        bits.set(4, false);

        let res = Felt::from_bits(&bits).unwrap();

        let x = res.view_bits();
        let y = Felt::from_bits(x).unwrap();

        assert_eq!(res, y);
    }

    #[test]
    fn bytes_round_trip() {
        let original = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let hash = Felt::from_be_bytes(original).unwrap();
        let bytes = hash.to_be_bytes();
        assert_eq!(bytes, original);
    }

    #[test]
    fn from_bytes_overflow() {
        // Field modulus
        assert_eq!(Felt::from_be_bytes(MODULUS_U8), Err(OverflowError));
        // Field modulus - 1
        let mut max_val = MODULUS_U8;
        max_val[31] -= 1;
        Felt::from_be_bytes(max_val).unwrap();
    }

    #[test]
    fn field_round_trip() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let original = Felt::from_be_bytes(bytes).unwrap();
        let fp = MontFelt::from(original);
        let hash = Felt::from(fp);
        assert_eq!(hash, original);
    }

    mod from_be_slice {
        use pretty_assertions_sorted::assert_eq;

        use super::*;

        #[test]
        fn round_trip() {
            let original = Felt::from_hex_str("abcdef0123456789").unwrap();
            let bytes = original.to_be_bytes();
            let result = Felt::from_be_slice(&bytes[..]).unwrap();

            assert_eq!(result, original);
        }

        #[test]
        fn too_long() {
            let original = Felt::from_hex_str("abcdef0123456789").unwrap();
            let mut bytes = original.to_be_bytes().to_vec();
            bytes.push(0);
            Felt::from_be_slice(&bytes[..]).unwrap_err();
        }

        #[test]
        fn short_slice() {
            let original = Felt::from_hex_str("abcdef0123456789").unwrap();
            let bytes = original.to_be_bytes();
            let result = Felt::from_be_slice(&bytes[24..]);

            assert_eq!(result, Ok(original));
        }

        #[test]
        fn max() {
            let mut max_val = MODULUS_U8;
            max_val[31] -= 1;
            Felt::from_be_slice(&max_val[..]).unwrap();
        }

        #[test]
        fn overflow() {
            assert_eq!(Felt::from_be_slice(&MODULUS_U8[..]), Err(OverflowError));
        }
    }

    mod fmt {
        use pretty_assertions_sorted::assert_eq;

        use super::Felt;

        #[test]
        fn debug() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let felt = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{felt:?}");

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);
            let expected = format!("Felt({felt})");

            assert_eq!(result, expected);
        }

        #[test]
        fn fmt() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{starkhash:x}");

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            // We don't really care which casing is used by fmt.
            assert_eq!(result.to_lowercase(), expected.to_lowercase());
        }

        #[test]
        fn lower_hex() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{starkhash:x}");

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            assert_eq!(result, expected.to_lowercase());
        }

        #[test]
        fn upper_hex() {
            let hex_str = "1234567890abcdef000edcba0987654321";
            let starkhash = Felt::from_hex_str(hex_str).unwrap();
            let result = format!("{starkhash:X}");

            let mut expected = "0".repeat(64 - hex_str.len());
            expected.push_str(hex_str);

            assert_eq!(result, expected.to_uppercase());
        }
    }

    mod from_hex_str {
        use assert_matches::assert_matches;
        use pretty_assertions_sorted::assert_eq;

        use super::*;

        /// Test hex string with its expected [Felt].
        fn test_data() -> (&'static str, Felt) {
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
            let expected = Felt::from_be_bytes(expected).unwrap();

            ("0123456789abcdefABCDEF", expected)
        }

        #[test]
        fn simple() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(test_str).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn prefix() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(&format!("0x{test_str}")).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn leading_zeros() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(&format!("000000000{test_str}")).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn prefix_and_leading_zeros() {
            let (test_str, expected) = test_data();
            let uut = Felt::from_hex_str(&format!("0x000000000{test_str}")).unwrap();
            assert_eq!(uut, expected);
        }

        #[test]
        fn invalid_nibble() {
            assert_matches!(Felt::from_hex_str("0x123z").unwrap_err(), HexParseError::InvalidNibble(n) => assert_eq!(n, b'z'))
        }

        #[test]
        fn invalid_len() {
            assert_matches!(Felt::from_hex_str(&"1".repeat(65)).unwrap_err(), HexParseError::InvalidLength{max: 64, actual: n} => assert_eq!(n, 65))
        }

        #[test]
        fn overflow() {
            // Field modulus
            let mut modulus =
                "0x800000000000011000000000000000000000000000000000000000000000001".to_string();
            assert_eq!(
                Felt::from_hex_str(&modulus).unwrap_err(),
                HexParseError::Overflow
            );
            // Field modulus - 1
            modulus.pop();
            modulus.push('0');
            Felt::from_hex_str(&modulus).unwrap();
        }
    }

    mod to_hex_str {
        use pretty_assertions_sorted::assert_eq;

        use super::*;

        const ODD: &str = "0x1234567890abcde";
        const EVEN: &str = "0x1234567890abcdef";
        const MAX: &str = "0x800000000000011000000000000000000000000000000000000000000000000";

        #[test]
        fn zero() {
            assert_eq!(Felt::ZERO.to_hex_str(), "0x0");
            let mut buf = [0u8; 66];
            assert_eq!(Felt::ZERO.as_hex_str(&mut buf), "0x0");
        }

        #[test]
        fn odd() {
            let hash = Felt::from_hex_str(ODD).unwrap();
            assert_eq!(hash.to_hex_str(), ODD);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), ODD);
        }

        #[test]
        fn even() {
            let hash = Felt::from_hex_str(EVEN).unwrap();
            assert_eq!(hash.to_hex_str(), EVEN);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), EVEN);
        }

        #[test]
        fn max() {
            let hash = Felt::from_hex_str(MAX).unwrap();
            assert_eq!(hash.to_hex_str(), MAX);
            let mut buf = [0u8; 66];
            assert_eq!(hash.as_hex_str(&mut buf), MAX);
        }

        #[test]
        #[should_panic]
        fn buffer_too_small() {
            let mut buf = [0u8; 65];
            Felt::ZERO.as_hex_str(&mut buf);
        }
    }

    mod has_more_than_251_bits {
        use super::*;

        #[test]
        fn has_251_bits() {
            let mut bytes = [0xFFu8; 32];
            bytes[0] = 0x07;
            let h = Felt::from_be_bytes(bytes).unwrap();
            assert!(!h.has_more_than_251_bits());
        }

        #[test]
        fn has_252_bits() {
            let mut bytes = [0u8; 32];
            bytes[0] = 0x08;
            let h = Felt::from_be_bytes(bytes).unwrap();
            assert!(h.has_more_than_251_bits());
        }
    }
}
