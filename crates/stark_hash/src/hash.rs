use stark_curve::{AffinePoint, FieldElement, ProjectivePoint, PEDERSEN_P0};

use bitvec::{field::BitField, slice::BitSlice};

use crate::Felt;

include!(concat!(env!("OUT_DIR"), "/curve_consts.rs"));

/// Computes the [Starknet Pedersen hash] on `a` and `b` using precomputed points.
///
/// [Starknet Pedersen hash]: https://docs.starkware.co/starkex-v3/crypto/pedersen-hash-function
pub fn stark_hash(a: Felt, b: Felt) -> Felt {
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
    Felt::from(result.x)
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let a = Felt::from_be_bytes(parse_hex(a)).unwrap();
        let b = Felt::from_be_bytes(parse_hex(b)).unwrap();
        let expected = Felt::from_be_bytes(parse_hex(expected)).unwrap();

        let hash = stark_hash(a, b);
        let hash2 = stark_hash(a, b);

        assert_eq!(hash, hash2);
        assert_eq!(hash, expected);
    }
}
