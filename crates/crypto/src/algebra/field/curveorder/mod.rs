mod additive;
mod cmp;
mod constants;
mod convert;
mod division;
mod inverse;
mod multiplicative;
mod parity;
mod random;
mod reduce;

/// CMontgomery Field Element with modulo
/// p = 3618502788666131213697322783095070105526743751716087489154079457884512865583
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CurveOrderMontFelt(pub [u64; 4]);

impl std::fmt::Debug for crate::CurveOrderMontFelt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reduced = self.reduce_full();
        write!(f, "CurveOrderMontFelt({:?})", reduced.0)
    }
}

impl crate::CurveOrderMontFelt {}
