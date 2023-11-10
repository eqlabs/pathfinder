use crate::algebra::curve::CURVE_ORDER;
use crate::algebra::field::derive::{derive_op, derive_op_assign};
use crate::algebra::field::{Felt, MontFelt};
use ark_ff::fields::{Fp256, MontBackend};
use ark_ff::{BigInt, BigInteger, Field, MontConfig, PrimeField, UniformRand};
use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use rand::Rng;

/// Configuration for the curve-order field used for curve scalars
#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[generator = "3"]
pub struct FrConfig;

/// Curve-order field element in Montgomery representation
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

/// Montgomery Field Element in the curve-order field
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurveOrderMontFelt(Fr);

/// Create constant MontFelt from a decimal string.
macro_rules! curveordermontfelt_dec {
    ($x:expr) => {
        $crate::algebra::field::CurveOrderMontFelt::new(ark_ff::MontFp!($x))
    };
}
pub(crate) use curveordermontfelt_dec;

impl CurveOrderMontFelt {
    /// Constant zero
    pub const ZERO: Self = curveordermontfelt_dec!("0");

    /// Constant one
    pub const ONE: Self = curveordermontfelt_dec!("1");

    /// Constant two
    pub const TWO: Self = curveordermontfelt_dec!("2");

    /// Constant three
    pub const THREE: Self = curveordermontfelt_dec!("3");
}

impl CurveOrderMontFelt {
    /// Create a field element
    pub const fn new(x: Fr) -> Self {
        CurveOrderMontFelt(x)
    }

    /// Sample a random field element
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        CurveOrderMontFelt(Fr::rand(rng))
    }

    /// Get raw representation of field element
    pub fn raw(&self) -> [u64; 4] {
        self.0 .0 .0
    }

    /// Create a field element from raw representation
    pub const fn from_raw(x: [u64; 4]) -> Self {
        CurveOrderMontFelt(Fr::new_unchecked(BigInt::new(x)))
    }

    /// Parse a field element from big-endian bytes modulo the order
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        CurveOrderMontFelt(Fr::from_be_bytes_mod_order(bytes))
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
        CurveOrderMontFelt(self.0.square())
    }

    /// Compute inverse of a field element
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(CurveOrderMontFelt)
    }

    /// Compute square root of an element.
    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(CurveOrderMontFelt)
    }
}

impl TryFrom<MontFelt> for CurveOrderMontFelt {
    type Error = ();
    fn try_from(value: MontFelt) -> Result<Self, Self::Error> {
        if value < CURVE_ORDER {
            let bytes = value.to_be_bytes();
            Ok(Self::from_be_bytes(&bytes))
        } else {
            Err(())
        }
    }
}

impl TryFrom<Felt> for CurveOrderMontFelt {
    type Error = ();
    /// Converts a felt element to a curve-order field element if less than the curve order
    fn try_from(value: Felt) -> Result<Self, Self::Error> {
        let montvalue = MontFelt::from(value);
        if montvalue < CURVE_ORDER {
            Ok(Self::from_be_bytes(value.as_be_bytes()))
        } else {
            Err(())
        }
    }
}

impl From<u64> for CurveOrderMontFelt {
    fn from(value: u64) -> Self {
        CurveOrderMontFelt::try_from(Felt::from(value)).expect("u64 fit in field")
    }
}
impl From<u128> for CurveOrderMontFelt {
    fn from(value: u128) -> Self {
        CurveOrderMontFelt::try_from(Felt::from(value)).expect("u128 fit in field")
    }
}

impl PartialOrd for CurveOrderMontFelt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl std::ops::Neg for CurveOrderMontFelt {
    type Output = Self;
    fn neg(self) -> Self::Output {
        CurveOrderMontFelt(-self.0)
    }
}

derive_op!(CurveOrderMontFelt, Add, add, +);
derive_op!(CurveOrderMontFelt, Sub, sub, -);
derive_op!(CurveOrderMontFelt, Mul, mul, *);
derive_op!(CurveOrderMontFelt, Div, div, /);
derive_op_assign!(CurveOrderMontFelt, AddAssign, add_assign, +=);
derive_op_assign!(CurveOrderMontFelt, SubAssign, sub_assign, -=);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orderfield_boundary() {
        // Both zero, one and p-1 should succeed
        assert!(CurveOrderMontFelt::try_from(MontFelt::ZERO).is_ok());
        assert!(CurveOrderMontFelt::try_from(MontFelt::ONE).is_ok());
        assert!(CurveOrderMontFelt::try_from(CURVE_ORDER - MontFelt::ONE).is_ok());

        // But p, p+1 and p+2 should fail
        assert!(CurveOrderMontFelt::try_from(CURVE_ORDER).is_err());
        assert!(CurveOrderMontFelt::try_from(CURVE_ORDER + MontFelt::ONE).is_err());
        assert!(CurveOrderMontFelt::try_from(CURVE_ORDER + MontFelt::TWO).is_err());
    }
}
