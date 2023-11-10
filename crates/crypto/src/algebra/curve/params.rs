//! Constants for the stark curve, see the <https://docs.starkware.co/starkex/crypto/stark-curve.html>
use crate::algebra::curve::projective::projective_point_str;
use crate::algebra::curve::*;
use crate::algebra::field::*;

/// Order of the curve.
pub const CURVE_ORDER: MontFelt =
    montfelt_dec!("3618502788666131213697322783095070105526743751716087489154079457884512865583");

/// Constant `a` from curve equation
pub const CURVE_A: MontFelt = MontFelt::ONE;

/// Constant `b` from curve equation
pub const CURVE_B: MontFelt =
    montfelt_dec!("3141592653589793238462643383279502884197169399375105820974944592307816406665");

/// Montgomery representation of the Stark curve generator G.
pub const CURVE_G: ProjectivePoint = projective_point_str!(
    "874739451078007766457464989774322083649278607533249481151382481072868806602",
    "152666792071518830868575557812948353041420400780739481342941381225525861407"
);
