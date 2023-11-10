use crate::algebra::field::derive::*;
use crate::algebra::field::{CurveOrderMontFelt, Felt};
use ark_ff::fields::{Fp256, MontBackend};
use ark_ff::{BigInt, BigInteger, Field, MontConfig, PrimeField, UniformRand};
use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use rand::Rng;

/// Configuration for Stark base-field.
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct FqConfig;

/// Finite field with ark_ff backend.
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

/// Montgomery Field Element.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MontFelt(Fq);

/// Create constant MontFelt from a decimal string.
macro_rules! montfelt_dec {
    ($x:expr) => {
        $crate::algebra::field::MontFelt::new(ark_ff::MontFp!($x))
    };
}
pub(crate) use montfelt_dec;

impl MontFelt {
    /// Constant zero
    pub const ZERO: Self = montfelt_dec!("0");

    /// Constant one
    pub const ONE: Self = montfelt_dec!("1");

    /// Constant two
    pub const TWO: Self = montfelt_dec!("2");

    /// Constant three
    pub const THREE: Self = montfelt_dec!("3");
}

impl MontFelt {
    /// Create a field element
    pub const fn new(x: Fq) -> Self {
        MontFelt(x)
    }

    /// Sample a random field element
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        MontFelt(Fq::rand(rng))
    }

    /// Get raw representation of field element
    pub fn raw(&self) -> [u64; 4] {
        self.0 .0 .0
    }

    /// Create a field element from raw representation
    pub const fn from_raw(x: [u64; 4]) -> Self {
        MontFelt(Fq::new_unchecked(BigInt::new(x)))
    }

    /// Parse a field element from big-endian bytes modulo the order
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        MontFelt(Fq::from_be_bytes_mod_order(bytes))
    }

    /// Convert a field element to big-endian bytes
    pub fn to_be_bytes(&self) -> [u8; 32] {
        // safe since bytes length match
        self.0.into_bigint().to_bytes_be().try_into().unwrap()
    }

    /// Convert a field element to little-endian bits
    pub fn into_le_bits(self) -> BitArray<[u64; 4], Lsb0> {
        self.0.into_bigint().0.into()
    }

    /// Compute the square of a field element
    pub fn square(&self) -> Self {
        MontFelt(self.0.square())
    }

    /// Compute inverse of a field element
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(MontFelt)
    }

    /// Compute square root of an element.
    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(MontFelt)
    }
}

impl From<Felt> for MontFelt {
    fn from(felt: Felt) -> Self {
        // safe since the value is below field order
        debug_assert_eq!(std::mem::size_of::<MontFelt>(), std::mem::size_of::<Felt>());
        MontFelt::from_be_bytes(felt.as_be_bytes())
    }
}

impl From<CurveOrderMontFelt> for MontFelt {
    fn from(value: CurveOrderMontFelt) -> Self {
        // safe since the value is below field order
        let bytes = value.to_be_bytes();
        MontFelt::from_be_bytes(&bytes)
    }
}

impl From<u64> for MontFelt {
    fn from(value: u64) -> Self {
        MontFelt::from(Felt::from(value))
    }
}
impl From<u128> for MontFelt {
    fn from(value: u128) -> Self {
        MontFelt::from(Felt::from(value))
    }
}

impl PartialOrd for MontFelt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl std::ops::Neg for MontFelt {
    type Output = Self;
    fn neg(self) -> Self::Output {
        MontFelt(-self.0)
    }
}

derive_op!(MontFelt, Add, add, +);
derive_op!(MontFelt, Sub, sub, -);
derive_op!(MontFelt, Mul, mul, *);
derive_op!(MontFelt, Div, div, /);
derive_op_assign!(MontFelt, AddAssign, add_assign, +=);
derive_op_assign!(MontFelt, SubAssign, sub_assign, -=);
