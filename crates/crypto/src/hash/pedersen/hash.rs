use bitvec::field::BitField;
use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;
use bitvec::view::BitView;

use crate::algebra::curve::*;
use crate::algebra::field::*;
use crate::hash::pedersen::consts::*;
use crate::hash::pedersen::gens::*;

/// Computes the [Starknet Pedersen hash] of `(a,b)`.
///
/// [Starknet Pedersen hash]: https://docs.starkware.co/starkex/crypto/pedersen-hash-function.html
pub fn pedersen_hash(a: Felt, b: Felt) -> Felt {
    let a = a.to_le_bytes();
    let b = b.to_le_bytes();
    let a_bits = a.view_bits::<Lsb0>();
    let b_bits = b.view_bits::<Lsb0>();

    // Preprocessed material is lookup-tables for each chunk of bits
    let table_size = (1 << CURVE_CONSTS_BITS) - 1;
    let add_points = |acc: &mut XYZZPoint, bits: &BitSlice<u8, _>, prep: &[AffinePoint]| {
        bits.chunks(CURVE_CONSTS_BITS)
            .enumerate()
            .for_each(|(i, v)| {
                let offset: usize = v.load_le();
                if offset > 0 {
                    // Table lookup at 'offset-1' in table for chunk 'i'
                    // We can add unchecked, since acc and prep. point cannot be infinity.
                    acc.add_affine_unchecked(&prep[i * table_size + offset - 1]);
                }
            });
    };

    // Compute hash
    let mut acc = XYZZPoint::from(&PEDERSEN_P0);

    add_points(&mut acc, &a_bits[..248], &CURVE_CONSTS_P1); // Add a_low * P1
    add_points(&mut acc, &a_bits[248..252], &CURVE_CONSTS_P2); // Add a_high * P2
    add_points(&mut acc, &b_bits[..248], &CURVE_CONSTS_P3); // Add b_low * P3
    add_points(&mut acc, &b_bits[248..252], &CURVE_CONSTS_P4); // Add b_high * P4

    // Convert to affine
    let result = AffinePoint::from(&acc);

    // Return x-coordinate
    Felt::from(result.x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pedersen() {
        // Test vector from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/pedersen_hash_test.cc
        let a =
            Felt::from_hex_str("03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb")
                .unwrap();
        let b =
            Felt::from_hex_str("0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a")
                .unwrap();
        let expected =
            Felt::from_hex_str("030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662")
                .unwrap();

        let hash = pedersen_hash(a, b);
        assert_eq!(hash, expected);
    }
}
