//! Constants for the stark curve, see the <https://docs.starkware.co/starkex/crypto/stark-curve.html>
use crate::algebra::curve::*;
use crate::algebra::field::*;

/// Order of the curve.
pub const CURVE_ORDER: MontFelt =
    MontFelt::from_hex("800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F");

/// Constant `a` from curve equation
pub const CURVE_A: MontFelt = MontFelt::ONE;

/// Constant `b` from curve equation
pub const CURVE_B: MontFelt =
    MontFelt::from_hex("6F21413EFBE40DE150E596D72F7A8C5609AD26C15C915C1F4CDFCB99CEE9E89");

/// Montgomery representation of the Stark curve generator G.
pub const CURVE_G: ProjectivePoint = ProjectivePoint::from_hex(
    "1EF15C18599971B7BECED415A40F0C7DEACFD9B0D1819E03D723D8BC943CFCA",
    "5668060AA49730B7BE4801DF46EC62DE53ECD11ABE43A32873000C36E8DC1F",
);
