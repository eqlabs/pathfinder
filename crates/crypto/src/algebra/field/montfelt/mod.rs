mod additive;
mod bits;
mod cmp;
mod constants;
mod convert;
mod core;
mod division;
mod hex;
mod inverse;
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
        let reduced = self.reduce_full();
        write!(f, "MontFelt({:?})", reduced.0)
    }
}

impl MontFelt {
    /// Create a field element from Montgomery representation
    pub const fn new(x: [u64; 4]) -> Self {
        Self(x)
    }

    /// Get raw representation of field element
    pub fn raw(&self) -> [u64; 4] {
        self.0
    }
}
