use bitvec::{array::BitArray, order::Lsb0};
use ff::PrimeField;

/// The field primitive used by Starkware's curve.
///
/// It's main use is to allow [`pedersen_hash`](crate::hash::pedersen_hash).
#[derive(PrimeField)]
#[PrimeFieldModulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "big"]
pub struct FieldElement([u64; 4]);

impl FieldElement {
    /// Construct a field element constant from montgomery representation
    pub const fn new(v: [u64; 4]) -> Self {
        Self(v)
    }

    pub fn inner(&self) -> [u64; 4] {
        self.0
    }

    /// Transforms [FieldElement] into little endian bit representation.
    pub fn into_bits(mut self) -> BitArray<Lsb0, [u64; 4]> {
        #[cfg(not(target_endian = "little"))]
        {
            todo!("untested and probably unimplemented: big-endian targets")
        }

        #[cfg(target_endian = "little")]
        {
            self.mont_reduce(
                self.0[0usize],
                self.0[1usize],
                self.0[2usize],
                self.0[3usize],
                0,
                0,
                0,
                0,
            );

            self.0.into()
        }
    }
}

/// Montgomery representation of one
pub const FIELD_ONE: FieldElement = FieldElement([
    18446744073709551585,
    18446744073709551615,
    18446744073709551615,
    576460752303422960,
]);
/// Montgomery representation of two
pub const FIELD_TWO: FieldElement = FieldElement([
    18446744073709551553,
    18446744073709551615,
    18446744073709551615,
    576460752303422416,
]);
/// Montgomery representation of three
pub const FIELD_THREE: FieldElement = FieldElement([
    18446744073709551521,
    18446744073709551615,
    18446744073709551615,
    576460752303421872,
]);

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pretty_assertions::assert_eq;

    #[test]
    fn bits_zero() {
        let zero = FieldElement::zero().into_bits();
        let expected = BitArray::<Lsb0, [u64; 4]>::default();

        assert_eq!(zero, expected);
    }

    #[test]
    fn bits_one() {
        let one = FieldElement::one().into_bits();

        let mut expected = BitArray::<Lsb0, [u64; 4]>::default();
        expected.set(0, true);

        assert_eq!(one, expected);
    }

    #[test]
    fn bits_two() {
        let two = (FieldElement::one() + FieldElement::one()).into_bits();

        let mut expected = BitArray::<Lsb0, [u64; 4]>::default();
        expected.set(1, true);

        assert_eq!(two, expected);
    }

    #[test]
    fn const_one_two_three() {
        let one = FieldElement::from(1);
        let two = FieldElement::from(2);
        let three = FieldElement::from(3);
        assert_eq!(FIELD_ONE, one);
        assert_eq!(FIELD_TWO, two);
        assert_eq!(FIELD_THREE, three);
    }
}
