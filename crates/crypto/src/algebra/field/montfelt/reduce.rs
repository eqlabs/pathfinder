use crate::algebra::field::core::{const_adc, const_mac};
use crate::MontFelt;

impl MontFelt {
    /// Reduce a field element max 2*(p-1)
    #[inline(always)]
    pub fn reduce_partial_assign(&mut self) {
        if self.const_geq(&MontFelt::P) {
            self.sub_assign_noreduce(&MontFelt::P);
        }
    }

    /// Reduce a field element max 2*(p-1)
    #[inline(always)]
    pub fn reduce_partial(mut self) -> MontFelt {
        self.reduce_partial_assign();
        self
    }

    /// Reduce a field element max 2*(p-1)
    #[inline(always)]
    pub const fn const_reduce_partial(&self) -> MontFelt {
        if self.const_geq(&MontFelt::P) {
            return self.const_sub_noreduce(&MontFelt::P);
        }
        *self
    }

    /// Full reduction computing x * R^{-1} mod p
    #[inline(always)]
    pub fn reduce_full(&self) -> MontFelt {
        MontFelt::mont_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    /// Full reduction computing x * R^{-1} mod p
    #[inline(always)]
    pub const fn const_reduce_full(&self) -> MontFelt {
        MontFelt::const_mont_reduce(self.0[0], self.0[1], self.0[2], self.0[3], 0, 0, 0, 0)
    }

    /// Reduce a field element max (p-1)^2
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub const fn const_mont_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> MontFelt {
        let k = r0.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r0, 0);
        let (r1, carry) = const_mac(k, Self::P.0[1], r1, carry);
        let (r2, carry) = const_mac(k, Self::P.0[2], r2, carry);
        let (r3, carry) = const_mac(k, Self::P.0[3], r3, carry);
        let (r4, carry2) = const_adc(r4, 0, carry);

        let k = r1.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r1, 0);
        let (r2, carry) = const_mac(k, Self::P.0[1], r2, carry);
        let (r3, carry) = const_mac(k, Self::P.0[2], r3, carry);
        let (r4, carry) = const_mac(k, Self::P.0[3], r4, carry);
        let (r5, carry2) = const_adc(r5, carry2, carry);

        let k = r2.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r2, 0);
        let (r3, carry) = const_mac(k, Self::P.0[1], r3, carry);
        let (r4, carry) = const_mac(k, Self::P.0[2], r4, carry);
        let (r5, carry) = const_mac(k, Self::P.0[3], r5, carry);
        let (r6, carry2) = const_adc(r6, carry2, carry);

        let k = r3.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r3, 0);
        let (r4, carry) = const_mac(k, Self::P.0[1], r4, carry);
        let (r5, carry) = const_mac(k, Self::P.0[2], r5, carry);
        let (r6, carry) = const_mac(k, Self::P.0[3], r6, carry);
        let (r7, _) = const_adc(r7, carry2, carry);

        let r = MontFelt([r4, r5, r6, r7]);
        r.const_reduce_partial()
    }

    /// Reduce a field element max (p-1)^2
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn mont_reduce(
        r0: u64,
        r1: u64,
        r2: u64,
        r3: u64,
        r4: u64,
        r5: u64,
        r6: u64,
        r7: u64,
    ) -> MontFelt {
        let k = r0.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r0, 0);
        let (r1, carry) = const_mac(k, Self::P.0[1], r1, carry);
        let (r2, carry) = const_mac(k, Self::P.0[2], r2, carry);
        let (r3, carry) = const_mac(k, Self::P.0[3], r3, carry);
        let (r4, carry2) = const_adc(r4, 0, carry);

        let k = r1.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r1, 0);
        let (r2, carry) = const_mac(k, Self::P.0[1], r2, carry);
        let (r3, carry) = const_mac(k, Self::P.0[2], r3, carry);
        let (r4, carry) = const_mac(k, Self::P.0[3], r4, carry);
        let (r5, carry2) = const_adc(r5, carry2, carry);

        let k = r2.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r2, 0);
        let (r3, carry) = const_mac(k, Self::P.0[1], r3, carry);
        let (r4, carry) = const_mac(k, Self::P.0[2], r4, carry);
        let (r5, carry) = const_mac(k, Self::P.0[3], r5, carry);
        let (r6, carry2) = const_adc(r6, carry2, carry);

        let k = r3.wrapping_mul(Self::M0);
        let (_, carry) = const_mac(k, Self::P.0[0], r3, 0);
        let (r4, carry) = const_mac(k, Self::P.0[1], r4, carry);
        let (r5, carry) = const_mac(k, Self::P.0[2], r5, carry);
        let (r6, carry) = const_mac(k, Self::P.0[3], r6, carry);
        let (r7, _) = const_adc(r7, carry2, carry);

        let r = MontFelt([r4, r5, r6, r7]);
        r.reduce_partial()
    }
}
