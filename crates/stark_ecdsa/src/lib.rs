use stark_curve::*;
use stark_hash::Felt;

pub type Signature = (FieldElement, FieldElement);

// Upper bound is 0x0800000000000000000000000000000000000000000000000000000000000000
// in Montgomery representation. We could also use Felt::has_more_than_251_bits, but
// this is more consistent with StarkWare's implementation.
pub const UPPER_BOUND: FieldElement = FieldElement::new([
    18446743986131435553,
    160989183,
    18446744073709255680,
    576459263475450960,
]);

/// Generate the public-key from a secret-key.
pub fn get_pk(sk: &FieldElement) -> ProjectivePoint {
    stark_curve::CURVE_G.multiply_elm(sk)
}

/// Verify an ECDSA signature with a partial public key.
pub fn ecdsa_verify_partial(pk: &Felt, z: &Felt, r: &Felt, s: &Felt) -> bool {
    // Check the public key is on the curve
    let f_pk = FieldElement::from(*pk);
    let point_pk = match ProjectivePoint::from_x(f_pk) {
        Some(p) => p,
        None => return false,
    };

    // Standard verify
    ecdsa_verify(&point_pk, z, r, s)
}

/// Verify an ECDSA signature (r,s) on message z with public key pk.
pub fn ecdsa_verify(pk: &ProjectivePoint, z: &Felt, r: &Felt, s: &Felt) -> bool {
    // Convert to field elements
    let f_z = FieldElement::from(*z);
    let f_r = FieldElement::from(*r);
    let f_s = FieldElement::from(*s);

    let cf_z = CurveOrderFieldElement::from_elm(f_z).unwrap();
    let cf_r = CurveOrderFieldElement::from_elm(f_r).unwrap();
    let cf_s = CurveOrderFieldElement::from_elm(f_s).unwrap();

    // Check hard bound on message and signature, see Starkware impl.
    if f_z == FieldElement::ZERO || f_z >= UPPER_BOUND {
        return false;
    }
    if f_r == FieldElement::ZERO || f_r >= UPPER_BOUND {
        return false;
    }
    if f_s == FieldElement::ZERO || f_s >= UPPER_BOUND {
        return false;
    }

    // In normal ECDSA, we compute the inverse here, but not in StarkWare's reference impl.
    // let cf_s = cf_s.invert().unwrap();
    let u1 = (cf_z * cf_s).to_elm();
    let u2 = (cf_r * cf_s).to_elm();

    // Compute r1 = u1*G + u2*pk and r2 = u1*G - u2*pk
    let u1g = CURVE_G.multiply_elm(&u1);
    let u2pk = pk.multiply_elm(&u2);
    let r1 = {
        let mut tmp = u1g.clone();
        tmp.add(&u2pk);
        AffinePoint::from(&tmp)
    };
    let r2 = {
        let mut minus_u2pk = u2pk.clone();
        minus_u2pk.negate();

        let mut tmp = u1g;
        tmp.add(&minus_u2pk);
        AffinePoint::from(&tmp)
    };

    // Return whether signature was valid
    r1.x == f_r || r2.x == f_r
}

/// Test vectors from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/ecdsa_test.cc
#[cfg(test)]
mod tests {
    use stark_hash::Felt;

    use super::*;

    fn felt_hex(x: &str) -> Felt {
        Felt::from_hex_str(x).unwrap()
    }
    fn felm_hex(x: &str) -> FieldElement {
        FieldElement::from(Felt::from_hex_str(x).unwrap())
    }

    #[test]
    fn test_upper_bound() {
        assert!(UPPER_BOUND <= stark_curve::CURVE_ORDER);
    }

    #[test]
    fn test_get_pk() {
        let sk = felm_hex("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc");

        let pk_x = felm_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let pk_y = felm_hex("54d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06");

        let pk = get_pk(&sk);
        let pk_affine = AffinePoint::from(&pk);

        assert_eq!(pk_affine.x, pk_x);
        assert_eq!(pk_affine.y, pk_y);
    }

    #[test]
    fn test_from_x() {
        let pk_x = felm_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let pk_y = felm_hex("54d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06");
        let pk_affine = AffinePoint::from_x(pk_x).unwrap();
        assert_eq!(pk_affine.y, pk_y);
    }

    #[test]
    fn test_verify() {
        let pk_x = felm_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let pk_y = felm_hex("54d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06");
        let pk = ProjectivePoint::from_x(pk_x).unwrap();
        assert_eq!(pk.y, pk_y);

        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");

        assert!(ecdsa_verify(&pk, &msg, &r, &s));
    }

    #[test]
    fn test_verify_bad() {
        // Changed last byte of pk from 3 to 4
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea44");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");
        assert!(!ecdsa_verify_partial(&pk, &msg, &r, &s));

        // Changed last byte of msg from f to 0
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a30");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");
        assert!(!ecdsa_verify_partial(&pk, &msg, &r, &s));

        // Changed last byte of r from 2 to 3
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e883");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");
        assert!(!ecdsa_verify_partial(&pk, &msg, &r, &s));

        // Changed last byte of s from e to f
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286f");
        assert!(!ecdsa_verify_partial(&pk, &msg, &r, &s));
    }
}
