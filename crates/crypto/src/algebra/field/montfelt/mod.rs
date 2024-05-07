mod additive;
mod cmp;
mod constants;
mod convert;
mod division;
mod hex;
mod inverse;
mod mont;
mod multiplicative;
mod parity;
mod pow;
mod random;
mod reduce;
mod sqrt;

/// Montgomery Field Element with modulo
/// p = 3618502788666131213697322783095070105623107215331596699973092056135872020481
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MontFelt(pub [u64; 4]);

impl std::fmt::Debug for MontFelt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // debug prints the montgomery representation
        write!(f, "MontFelt(0x{})", self.to_hex())
    }
}

impl std::fmt::Display for MontFelt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // display prints the native representation
        let reduced = self.reduce_full();
        write!(f, "0x{}", reduced.to_hex())
    }
}
