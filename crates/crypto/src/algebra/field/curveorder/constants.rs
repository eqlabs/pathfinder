use crate::CurveOrderMontFelt;

impl CurveOrderMontFelt {
    /// The modulus of the field
    pub const P: CurveOrderMontFelt = CurveOrderMontFelt([
        2190616671734353199u64,
        13222870243701404210u64,
        18446744073709551615u64,
        576460752303423504u64,
    ]);

    /// Number of zero-bits in the most-significant limb
    pub const ZERO_BITS: u32 = 4;

    /// Montgomery constant R being 2^256 mod p
    pub const R: [u64; 4] = [
        5877859471073257295u64,
        14366136140576156654u64,
        8u64,
        576460752303422961u64,
    ];

    /// Montgomery constant R^2
    pub const R2: [u64; 4] = [
        6927015553468754061u64,
        5808788430323081401u64,
        13470454832524147387u64,
        565735549540988526u64,
    ];

    /// Constant `M0=-N[0]` where `R*R^{-1} - N*N^{-1} = 1`.
    pub const M0: u64 = 13504954208620504625u64;

    /// Constant zero
    pub const ZERO: Self = CurveOrderMontFelt([0u64; 4]);

    /// Constant one, also equal to Montgomery constant R
    pub const ONE: Self = CurveOrderMontFelt(Self::R);
}
