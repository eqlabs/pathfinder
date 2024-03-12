use crate::MontFelt;

impl MontFelt {
    /// The modulus of the field
    pub const P: MontFelt = MontFelt([1u64, 0u64, 0u64, 576460752303423505u64]);

    /// Number of zero-bits in the most-significant limb
    pub const ZERO_BITS: u32 = 4;

    /// Montgomery constant R being 2^256 mod p
    pub const R: [u64; 4] = [
        18446744073709551585u64,
        18446744073709551615u64,
        18446744073709551615u64,
        576460752303422960u64,
    ];

    /// Montgomery constant R^2
    pub const R2: [u64; 4] = [
        18446741271209837569u64,
        5151653887u64,
        18446744073700081664u64,
        576413109808302096u64,
    ];

    /// Constant `M0=-N[0]` where `R*R^{-1} - N*N^{-1} = 1`.
    pub const M0: u64 = 18446744073709551615u64;

    /// Constant zero
    pub const ZERO: Self = MontFelt([0u64; 4]);

    /// Constant one, also equal to Montgomery constant R
    pub const ONE: Self = MontFelt(Self::R);

    /// Constant two
    pub const TWO: Self = Self::ONE.const_add(&Self::ONE);

    /// Constant three
    pub const THREE: Self = Self::TWO.const_add(&Self::ONE);

    /// Square-root trace `s` such that `p-1 = 2^s*t`.
    pub const SQRT_S: u32 = 192;

    /// Square-root root-of-unity `t` such that `p-1 = 2^s*t`
    pub const SQRT_T: [u64; 4] = [
        6949056764481957780u64,
        12472843725830775137u64,
        4540864625977790373u64,
        23224827470060794u64,
    ];

    /// Constant `(t-1)/2` for use in square-root computation
    pub const SQRT_T_MINUS_ONE_DIV2: [u64; 4] = [288230376151711752u64, 0, 0, 0];

    /// Return whether the value is zero
    pub const fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Return whether the value is one
    pub const fn is_one(&self) -> bool {
        self.0[0] == MontFelt::R[0]
            && self.0[1] == MontFelt::R[1]
            && self.0[2] == MontFelt::R[2]
            && self.0[3] == MontFelt::R[3]
    }
}
