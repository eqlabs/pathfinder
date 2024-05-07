use crate::MontFelt;

impl MontFelt {
    /// Full reduction computing x * R^{-1} mod p
    #[inline(always)]
    pub fn to_native(&self) -> MontFelt {
        MontFelt::mont_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    /// Full reduction computing x * R^{-1} mod p
    #[inline(always)]
    pub const fn const_to_native(&self) -> MontFelt {
        MontFelt::const_mont_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    /// Create a new field element from a big-integer representation
    #[inline(always)]
    pub const fn const_from_native(&self) -> Self {
        self.const_mul(&MontFelt(MontFelt::R2))
    }

    /// Convert a field element to little-endian bits
    #[inline(always)]
    pub fn from_native(&self) -> Self {
        self.mul(&MontFelt(MontFelt::R2))
    }

    /// Convert a field element to little-endian bits
    #[inline(always)]
    pub fn from_native_limbs(x: [u64; 4]) -> Self {
        MontFelt(x).mul(&MontFelt(MontFelt::R2))
    }
}
