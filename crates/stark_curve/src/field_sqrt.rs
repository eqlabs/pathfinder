//! This module implements square root for the field as a dirty fix,
//! because the `ff` does not implement the Tonelli-Shanks algorithm.
use crate::{FieldElement, FieldElementRepr};
use ark_ff::{
    fields::{Fp256, MontBackend, MontConfig},
    BigInteger,
};
use ff::{Field, PrimeField};

#[derive(MontConfig)]
#[modulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[generator = "3"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

/// Computes sqrt(x) for a field element x, or returns None if none exist.
pub fn field_sqrt(x: FieldElement) -> Option<FieldElement> {
    // If x is zero, return none
    if bool::from(x.is_zero()) {
        return None;
    }

    // Otherwise compute using ark_ff
    use ark_ff::fields::{Field, PrimeField};
    let bytes = x.to_repr().0;
    let ark_elm: Fr = ark_ff::Fp256::from_be_bytes_mod_order(&bytes);
    let ark_sqrt: Fr = match ark_elm.sqrt() {
        Some(sqrt) => sqrt,
        None => return None,
    };
    let bytes: [u8; 32] = ark_ff::Fp256::into_bigint(ark_sqrt)
        .to_bytes_be()
        .try_into()
        .unwrap();
    let elm = FieldElement::from_repr(FieldElementRepr(bytes));
    match bool::from(elm.is_some()) {
        true => Some(elm.unwrap()),
        false => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn test_sqrt_zero() {
        let zero = FieldElement::ZERO;
        let sqrt_zero = field_sqrt(zero);
        assert_eq!(sqrt_zero, None);
    }

    #[test]
    fn test_sqrt() {
        let x = FieldElement::THREE;
        let minus_x = FieldElement::ZERO - x;

        // Test sqrt(x^2) equals x or -x
        let y = x.square();
        let sqrt_y = field_sqrt(y).unwrap();
        assert!(sqrt_y == x || sqrt_y == minus_x);

        // Test sqrt(x^4) equals x^2 or -x^2
        let minus_y = FieldElement::ZERO - y;
        let z = y.square();
        let sqrt_z = field_sqrt(z).unwrap();
        assert!(sqrt_z == y || sqrt_z == minus_y);
    }
}
