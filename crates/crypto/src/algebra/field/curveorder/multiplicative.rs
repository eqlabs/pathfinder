use crate::algebra::field::core::{const_adc, const_mac};
use crate::CurveOrderMontFelt;

impl CurveOrderMontFelt {
    /// SOS multiplication algorithm
    #[inline(always)]
    pub const fn const_mul(&self, x: &CurveOrderMontFelt) -> CurveOrderMontFelt {
        let carry = 0;
        let (r0, carry) = const_mac(self.0[0], x.0[0], 0, carry);
        let (r1, carry) = const_mac(self.0[0], x.0[1], 0, carry);
        let (r2, carry) = const_mac(self.0[0], x.0[2], 0, carry);
        let (r3, carry) = const_mac(self.0[0], x.0[3], 0, carry);
        let r4 = carry;

        let carry = 0;
        let (r1, carry) = const_mac(self.0[1], x.0[0], r1, carry);
        let (r2, carry) = const_mac(self.0[1], x.0[1], r2, carry);
        let (r3, carry) = const_mac(self.0[1], x.0[2], r3, carry);
        let (r4, carry) = const_mac(self.0[1], x.0[3], r4, carry);
        let r5 = carry;

        let carry = 0;
        let (r2, carry) = const_mac(self.0[2], x.0[0], r2, carry);
        let (r3, carry) = const_mac(self.0[2], x.0[1], r3, carry);
        let (r4, carry) = const_mac(self.0[2], x.0[2], r4, carry);
        let (r5, carry) = const_mac(self.0[2], x.0[3], r5, carry);
        let r6 = carry;

        let carry = 0;
        let (r3, carry) = const_mac(self.0[3], x.0[0], r3, carry);
        let (r4, carry) = const_mac(self.0[3], x.0[1], r4, carry);
        let (r5, carry) = const_mac(self.0[3], x.0[2], r5, carry);
        let (r6, carry) = const_mac(self.0[3], x.0[3], r6, carry);
        let r7 = carry;

        CurveOrderMontFelt::mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// CIOS multiplication algorithm
    #[inline(always)]
    #[allow(unused)]
    pub const fn const_mul_cios(&self, x: &CurveOrderMontFelt) -> CurveOrderMontFelt {
        let mut r = [0u64; 4];

        let mut i = 0;
        while i < 4 {
            let mut carry1 = 0u64;
            let (lo, hi) = const_mac(self.0[0], x.0[i], r[0], carry1);
            r[0] = lo;
            carry1 = hi;

            let k = r[0].wrapping_mul(Self::M0);
            let (_, hi) = const_mac(k, Self::P.0[0], r[0], 0);
            let mut carry2 = hi;

            let mut j = 1;
            while j < 4 {
                let (lo, hi) = const_mac(self.0[j], x.0[i], r[j], carry1);
                r[j] = lo;
                carry1 = hi;

                let (lo, hi) = const_mac(k, Self::P.0[j], r[j], carry2);
                r[j - 1] = lo;
                carry2 = hi;

                j += 1;
            }
            r[3] = carry1 + carry2;

            i += 1;
        }

        let r = CurveOrderMontFelt(r);
        r.reduce_partial()
    }

    #[inline(always)]
    pub const fn square(&self) -> CurveOrderMontFelt {
        let carry = 0;
        let (r1, carry) = const_mac(self.0[0usize], self.0[1usize], 0, carry);
        let (r2, carry) = const_mac(self.0[0usize], self.0[2usize], 0, carry);
        let (r3, carry) = const_mac(self.0[0usize], self.0[3usize], 0, carry);
        let r4 = carry;

        let carry = 0;
        let (r3, carry) = const_mac(self.0[1usize], self.0[2usize], r3, carry);
        let (r4, carry) = const_mac(self.0[1usize], self.0[3usize], r4, carry);
        let r5 = carry;

        let carry = 0;
        let (r5, carry) = const_mac(self.0[2usize], self.0[3usize], r5, carry);
        let r6 = carry;

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let (r0, carry) = const_mac(self.0[0usize], self.0[0usize], 0, 0);
        let (r1, carry) = const_adc(r1, 0, carry);
        let (r2, carry) = const_mac(self.0[1usize], self.0[1usize], r2, carry);
        let (r3, carry) = const_adc(r3, 0, carry);
        let (r4, carry) = const_mac(self.0[2usize], self.0[2usize], r4, carry);
        let (r5, carry) = const_adc(r5, 0, carry);
        let (r6, carry) = const_mac(self.0[3usize], self.0[3usize], r6, carry);
        let (r7, _) = const_adc(r7, 0, carry);

        CurveOrderMontFelt::mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }
}

impl std::ops::Mul<Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        self.const_mul(&rhs)
    }
}

impl std::ops::Mul<&Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        self.const_mul(rhs)
    }
}

impl std::ops::Mul<&mut Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: &mut Self) -> Self::Output {
        self.const_mul(rhs)
    }
}

impl std::ops::MulAssign<Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.const_mul(&rhs);
    }
}

impl std::ops::MulAssign<&Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.const_mul(rhs);
    }
}

impl std::ops::MulAssign<&mut Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &mut Self) {
        *self = self.const_mul(rhs);
    }
}
