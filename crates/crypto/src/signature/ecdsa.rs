use crate::algebra::curve::{AffinePoint, ProjectivePoint, CURVE_G};
use crate::algebra::field::{CurveOrderMontFelt, Felt, MontFelt};
use std::fmt::{Display, Formatter};

/// Upper bound is 0x0800000000000000000000000000000000000000000000000000000000000000
/// in Montgomery representation. We could also use Felt::has_more_than_251_bits, but
/// makes comparison easy for MontFelts and is consistent with StarkWare's implementation.
pub const UPPER_BOUND: MontFelt = MontFelt::from_raw([
    18446743986131435553,
    160989183,
    18446744073709255680,
    576459263475450960,
]);

/// Signature error
#[derive(Debug, Eq, PartialEq)]
pub enum SignatureError {
    /// Error if the signature is invalid during verification.
    Signature,

    /// Error for invalid randomness.
    Randomness,

    /// Error for invalid message.
    Message,

    /// Error for invalid secret key.
    SecretKey,

    /// Error for invalid public key.
    PublicKey,
}

impl Display for SignatureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::Signature => write!(f, "invalid signature"),
            SignatureError::Message => write!(f, "invalid message"),
            SignatureError::Randomness => write!(f, "invalid randomness"),
            SignatureError::SecretKey => write!(f, "invalid secret key"),
            SignatureError::PublicKey => write!(f, "invalid public key"),
        }
    }
}

impl std::error::Error for SignatureError {}

/// Retrieve the partial public-key from a private key
pub fn get_pk(sk: Felt) -> Option<Felt> {
    CurveOrderMontFelt::try_from(sk)
        .map(ProjectivePoint::gen_multiply_elm)
        .as_ref()
        .map(AffinePoint::from)
        .map(|ap| ap.x)
        .map(Felt::from)
        .ok()
}

/// Generate a signature `(r,s)` on message z with secret key sk with `k` from thread_rng, not constant time!
///
/// This algorithm tries different random `k` from thread_rng until it finds a valid signature. The
/// algorithm is **NOT** constant time and care should be taken when used in timing-sensitive contexts.
pub fn ecdsa_sign(sk: Felt, z: Felt) -> Result<(Felt, Felt), SignatureError> {
    let rng = &mut rand::thread_rng();
    loop {
        let k = Felt::random(rng);
        match ecdsa_sign_k(sk, z, k) {
            Ok(sig) => return Ok(sig),
            Err(SignatureError::Randomness) => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Generate a signature `(r,s)` on message z with secret key sk and explicit randomness k, not constant time!
///
/// Never sign the same message with the same randomness twice, or your key my be extracted. The
/// algorithm is **NOT** constant time and care should be taken when used in timing-sensitive contexts.
pub fn ecdsa_sign_k(sk: Felt, z: Felt, k: Felt) -> Result<(Felt, Felt), SignatureError> {
    let sk = CurveOrderMontFelt::try_from(sk).map_err(|_| SignatureError::SecretKey)?;
    let z = CurveOrderMontFelt::try_from(z).map_err(|_| SignatureError::Message)?;
    let k = CurveOrderMontFelt::try_from(k).map_err(|_| SignatureError::Randomness)?;
    if k == CurveOrderMontFelt::ZERO {
        return Err(SignatureError::Randomness);
    }

    // Compute `r` - we require it fits in 251 bits (less than curve order).
    let x = AffinePoint::gen_multiply_elm(k).x;
    if x >= UPPER_BOUND {
        return Err(SignatureError::Randomness);
    }
    let r = CurveOrderMontFelt::try_from(x).unwrap();

    // Compute `s` - safe as non-zero `k` are invertible in prime fields.
    let kinv = k.inverse().unwrap();
    let s = kinv * (z + r * sk);

    let r = Felt::from(r);
    let s = Felt::from(s);
    Ok((r, s))
}

/// Retrieve the point for a public key while validating it's non-zero and on the curve.
fn get_pk_point(pk: MontFelt) -> Option<AffinePoint> {
    match AffinePoint::from_x(pk) {
        Some(p) if !p.infinity => Some(p),
        _ => None,
    }
}

/// Verify an ECDSA signature with a partial public key.
pub fn ecdsa_verify_partial(pk: Felt, z: Felt, r: Felt, s: Felt) -> Result<(), SignatureError> {
    let montpk = MontFelt::from(pk);
    let pk_point = get_pk_point(montpk).ok_or(SignatureError::PublicKey)?;
    let pk_proj = ProjectivePoint::from(&pk_point);
    ecdsa_verify_inner(pk_proj, z, r, s)
}

/// Verify an ECDSA signature `(r,s)` on message `z` given a full public key `pk=(x,y)`.
pub fn ecdsa_verify(pk: AffinePoint, z: Felt, r: Felt, s: Felt) -> Result<(), SignatureError> {
    let pk_point = get_pk_point(pk.x).ok_or(SignatureError::PublicKey)?;
    if pk_point.y != pk.y {
        return Err(SignatureError::PublicKey);
    }
    let pk_proj = ProjectivePoint::from(&pk_point);
    ecdsa_verify_inner(pk_proj, z, r, s)
}

/// Verify an ECDSA signature `(r,s)` on message `z` given a validated public key `pk`.
///
/// The caller should check that the public key is on the curve and not infinity.
pub fn ecdsa_verify_inner(
    pk: ProjectivePoint,
    z: Felt,
    r: Felt,
    s: Felt,
) -> Result<(), SignatureError> {
    // Convert to field elements
    let f_z = MontFelt::from(z);
    let f_r = MontFelt::from(r);
    let f_s = MontFelt::from(s);

    let cf_z = CurveOrderMontFelt::try_from(f_z).unwrap();
    let cf_r = CurveOrderMontFelt::try_from(f_r).unwrap();
    let cf_s = CurveOrderMontFelt::try_from(f_s).unwrap();

    // Check hard bound on message and signature.
    if f_z >= UPPER_BOUND {
        return Err(SignatureError::Message);
    }
    if f_r == MontFelt::ZERO || f_r >= UPPER_BOUND {
        return Err(SignatureError::Signature);
    }
    if f_s == MontFelt::ZERO || f_s >= UPPER_BOUND {
        return Err(SignatureError::Signature);
    }

    // Compute u1 = z/s and u2 = r/s
    let cf_s = cf_s.inverse().unwrap();
    let u1 = cf_z * cf_s;
    let u2 = cf_r * cf_s;

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
    if r1.x == f_r || r2.x == f_r {
        Ok(())
    } else {
        Err(SignatureError::Signature)
    }
}

/// Test vectors from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/ecdsa_test.cc
#[cfg(test)]
mod tests {
    use super::*;

    fn felt_hex(x: &str) -> Felt {
        Felt::from_hex_str(x).unwrap()
    }
    fn felm_hex(x: &str) -> MontFelt {
        MontFelt::from(Felt::from_hex_str(x).unwrap())
    }

    #[test]
    fn upper_bound() {
        assert!(UPPER_BOUND <= crate::algebra::curve::CURVE_ORDER);
    }

    #[test]
    fn test_get_pk() {
        let sk = felt_hex("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc");

        let pk_x = felm_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let pk_y = felm_hex("54d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06");

        let pk = get_pk(sk).expect("valid sk");
        let pk_affine = AffinePoint::from_x(pk.into()).unwrap();

        assert_eq!(pk_affine.x, pk_x);
        assert_eq!(pk_affine.y, pk_y);
    }

    #[test]
    fn from_x() {
        let pk_x = felm_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let pk_y = felm_hex("54d7beec5ec728223671c627557efc5c9a6508425dc6c900b7741bf60afec06");
        let pk_affine = AffinePoint::from_x(pk_x).unwrap();
        assert_eq!(pk_affine.y, pk_y);
    }

    #[test]
    fn get_partial_pk() {
        let pk_x = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");

        let sk = felt_hex("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc");
        let pk = get_pk(sk).unwrap();

        assert_eq!(pk, pk_x);
    }

    #[test]
    fn verify_partial() {
        let sk = felt_hex("03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let sig = ecdsa_sign(sk, msg).expect("can sign");
        let pk = get_pk(sk).expect("can get pk");
        assert!(ecdsa_verify_partial(pk, msg, sig.0, sig.1).is_ok());
    }

    #[test]
    fn verify_inner() {
        // Test vector from https://github.com/starkware-libs/crypto-cpp/blob/master/src/starkware/crypto/ecdsa_test.cc
        let pk_x = felm_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let pk = ProjectivePoint::from_x(pk_x).unwrap();

        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let w = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");

        // Compute s=1/w
        let w = CurveOrderMontFelt::try_from(MontFelt::from(w)).unwrap();
        let s = Felt::from(w.inverse().unwrap());

        assert!(ecdsa_verify_inner(pk, msg, r, s).is_ok());
    }

    #[test]
    fn verify_bad() {
        // Changed last byte of pk from 3 to 4
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea44");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");
        assert!(ecdsa_verify_partial(pk, msg, r, s).is_err());

        // Changed last byte of msg from f to 0
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a30");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");
        assert!(ecdsa_verify_partial(pk, msg, r, s).is_err());

        // Changed last byte of r from 2 to 3
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e883");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e");
        assert!(ecdsa_verify_partial(pk, msg, r, s).is_err());

        // Changed last byte of s from e to f
        let pk = felt_hex("77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43");
        let msg = felt_hex("397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f");
        let r = felt_hex("173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882");
        let s = felt_hex("1f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286f");
        assert!(ecdsa_verify_partial(pk, msg, r, s).is_err());
    }

    #[test]
    fn sequencer() {
        // Test vector from https://alpha-mainnet.starknet.io/feeder_gateway/get_signature?blockNumber=350000
        // and pk from https://alpha-mainnet.starknet.io/feeder_gateway/get_public_key?
        use crate::hash::poseidon::poseidon_hash_many;
        let state_diff_commitment =
            felm_hex("0x432e8e2ad833548e1c1077fc298991b055ba1e6f7a17dd332db98f4f428c56c");
        let block_hash =
            felm_hex("0x6f7342a680d7f99bdfdd859f587c75299e7ffabe62c071ded3a6d8a34cb132c");

        let msg = Felt::from(poseidon_hash_many(&[block_hash, state_diff_commitment]));
        let r = felt_hex("0x95e98f5b91d39ae2b1bf77447a4fc01725352ae8b0b2c0a3fe09d43d1d9e57");
        let s = felt_hex("0x541b2db8dae6d5ae24b34e427d251edc2e94dcffddd85f207e1b51f2f4bb1ef");
        let pk = felt_hex("0x48253ff2c3bed7af18bde0b611b083b39445959102d4947c51c4db6aa4f4e58");
        assert!(ecdsa_verify_partial(pk, msg, r, s).is_ok());
    }

    #[test]
    fn openzeppelin_signature() {
        // From https://testnet.starkscan.co/tx/0x0630a81628900577eea4b4a677767e57a56dabd730c2f64772ecbbde22ff485a
        let pk = felt_hex("792c60ec4fdfea7ce6409db046b8dde11f595911cb74906be02a87ae6a4f70d");
        let msg = felt_hex("0630a81628900577eea4b4a677767e57a56dabd730c2f64772ecbbde22ff485a");
        let r = felt_hex("176846ea9b114f4f27f0d4d3cefacb5f830513fbd2d2f69a1a4d7552ae040be");
        let s = felt_hex("601a87d6bc3e3a6513bafa1d449ffb3a0dd6cbe72f927a8e7271af0e8dd1302");
        assert!(ecdsa_verify_partial(pk, msg, r, s).is_ok());
    }
}
