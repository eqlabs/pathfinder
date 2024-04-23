use bitvec::prelude::*;

use crate::algebra::curve::consts::{G_CONSTS, G_CONSTS_BITS};
use crate::algebra::curve::{AffinePoint, ProjectivePoint};
use crate::algebra::field::CurveOrderMontFelt;

impl ProjectivePoint {
    /// Multiply the curve generator `G` by a curve order field element.
    ///
    /// This function uses preprocessed constants to speed up the computation.
    pub fn gen_multiply_elm(x: CurveOrderMontFelt) -> ProjectivePoint {
        let bits = x.into_le_bits();

        let table_size = (1 << G_CONSTS_BITS) - 1;
        let add_points =
            |acc: &mut ProjectivePoint, bits: &BitSlice<u64, _>, prep: &[AffinePoint]| {
                bits.chunks(G_CONSTS_BITS).enumerate().for_each(|(i, v)| {
                    let offset: usize = v.load_le();
                    if offset > 0 {
                        // Table lookup at 'offset-1' in table for chunk 'i'
                        acc.add_affine(&prep[i * table_size + offset - 1]);
                    }
                });
            };

        // Compute x*G
        let mut acc = ProjectivePoint::identity();
        add_points(&mut acc, bits.as_bitslice(), &G_CONSTS);
        acc
    }
}

impl AffinePoint {
    /// Multiply the curve generator `G` by a curve order field element.
    ///
    /// This function uses preprocessed constants to speed up the computation.
    pub fn gen_multiply_elm(x: CurveOrderMontFelt) -> AffinePoint {
        AffinePoint::from(&ProjectivePoint::gen_multiply_elm(x))
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions_sorted::assert_eq;

    use super::*;
    use crate::algebra::curve::CURVE_G;
    use crate::algebra::field::CurveOrderMontFelt;

    #[test]
    fn test_generator_mul() {
        let mut rng = rand::thread_rng();
        let x = CurveOrderMontFelt::random(&mut rng);

        let standard = AffinePoint::from(&CURVE_G.multiply_elm(&x));
        let lutbased = AffinePoint::gen_multiply_elm(x);

        assert_eq!(standard, lutbased);
    }
}
