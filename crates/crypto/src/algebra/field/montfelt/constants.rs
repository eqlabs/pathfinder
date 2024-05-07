use crate::MontFelt;

impl MontFelt {
    /// The modulus of the field,
    /// p=3618502788666131213697322783095070105623107215331596699973092056135872020481
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

    /// Constant `M0=-N[0]^{-1} mod 2^64`.
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

    /// Constant `(t-1)/2` for use in square-root computation
    pub const SQRT_T_MINUS_ONE_DIV2: [u64; 4] = [288230376151711752u64, 0, 0, 0];

    /// Precomputed constant `z` for use in square-root computation.
    ///
    /// It is required to be a non-quadratic residue (we use 3) lifted to `t`,
    /// i.e. `z=R*3^t`.
    pub const SQRT_Z: MontFelt = MontFelt([
        4685640052668284376u64,
        12298664652803292137u64,
        735711535595279732u64,
        514024103053294630u64,
    ]);
}
