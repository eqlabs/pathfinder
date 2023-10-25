use ff::PrimeField;

use crate::{FieldElement, FieldElementRepr, CURVE_ORDER};

#[derive(PrimeField)]
#[PrimeFieldModulus = "3618502788666131213697322783095070105526743751716087489154079457884512865583"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "big"]
pub struct CurveOrderFieldElement([u64; 4]);

impl CurveOrderFieldElement {
    pub fn from_elm(value: FieldElement) -> Option<Self> {
        if value < CURVE_ORDER {
            let bytes = value.to_repr().0;
            let repr = CurveOrderFieldElementRepr(bytes);
            Some(Self::from_repr(repr).unwrap())
        } else {
            None
        }
    }

    pub fn to_elm(&self) -> FieldElement {
        let bytes = self.to_repr().0;
        let repr = FieldElementRepr(bytes);
        FieldElement::from_repr(repr).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_orderfield_boundary() {
        // Both zero, one and p-1 should succeed
        assert!(CurveOrderFieldElement::from_elm(FieldElement::ZERO).is_some());
        assert!(CurveOrderFieldElement::from_elm(FieldElement::ONE).is_some());
        assert!(CurveOrderFieldElement::from_elm(CURVE_ORDER - FieldElement::ONE).is_some());

        // But p, p+1 and p+2 should fail
        assert!(CurveOrderFieldElement::from_elm(CURVE_ORDER).is_none());
        assert!(CurveOrderFieldElement::from_elm(CURVE_ORDER + FieldElement::ONE).is_none());
        assert!(CurveOrderFieldElement::from_elm(CURVE_ORDER + FieldElement::TWO).is_none());
    }
}
