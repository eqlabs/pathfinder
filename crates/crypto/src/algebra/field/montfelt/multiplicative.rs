use crate::algebra::field::core::{acc, const_adc, const_mac, mac};
use crate::MontFelt;

impl MontFelt {
    /// SOS multiplication algorithm
    #[inline(always)]
    pub const fn const_mul(&self, x: &MontFelt) -> MontFelt {
        // Compute a[0] * b
        let carry = 0;
        let (r0, carry) = const_mac(self.0[0], x.0[0], 0, carry);
        let (r1, carry) = const_mac(self.0[0], x.0[1], 0, carry);
        let (r2, carry) = const_mac(self.0[0], x.0[2], 0, carry);
        let (r3, carry) = const_mac(self.0[0], x.0[3], 0, carry);
        let r4 = carry;

        // Compute a[1] * b
        let carry = 0;
        let (r1, carry) = const_mac(self.0[1], x.0[0], r1, carry);
        let (r2, carry) = const_mac(self.0[1], x.0[1], r2, carry);
        let (r3, carry) = const_mac(self.0[1], x.0[2], r3, carry);
        let (r4, carry) = const_mac(self.0[1], x.0[3], r4, carry);
        let r5 = carry;

        // Compute a[2] * b
        let carry = 0;
        let (r2, carry) = const_mac(self.0[2], x.0[0], r2, carry);
        let (r3, carry) = const_mac(self.0[2], x.0[1], r3, carry);
        let (r4, carry) = const_mac(self.0[2], x.0[2], r4, carry);
        let (r5, carry) = const_mac(self.0[2], x.0[3], r5, carry);
        let r6 = carry;

        // Compute a[3] * b
        let carry = 0;
        let (r3, carry) = const_mac(self.0[3], x.0[0], r3, carry);
        let (r4, carry) = const_mac(self.0[3], x.0[1], r4, carry);
        let (r5, carry) = const_mac(self.0[3], x.0[2], r5, carry);
        let (r6, carry) = const_mac(self.0[3], x.0[3], r6, carry);
        let r7 = carry;

        // Montgomery reduction
        MontFelt::const_mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// SOS squaring algorithm
    #[inline(always)]
    pub const fn const_square(&self) -> MontFelt {
        // Compute sum of a[i] * b[j] for i<j
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

        // Double it
        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        // Add the diagonal a[i] * b[i]
        let (r0, carry) = const_mac(self.0[0usize], self.0[0usize], 0, 0);
        let (r1, carry) = const_adc(r1, 0, carry);
        let (r2, carry) = const_mac(self.0[1usize], self.0[1usize], r2, carry);
        let (r3, carry) = const_adc(r3, 0, carry);
        let (r4, carry) = const_mac(self.0[2usize], self.0[2usize], r4, carry);
        let (r5, carry) = const_adc(r5, 0, carry);
        let (r6, carry) = const_mac(self.0[3usize], self.0[3usize], r6, carry);
        let (r7, _) = const_adc(r7, 0, carry);

        // Montgomery reduction
        MontFelt::const_mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    /// CIOS multiplication algorithm
    #[inline(always)]
    #[allow(unused)]
    pub fn mul(&self, x: &MontFelt) -> MontFelt {
        let a = &self.0;
        let b = &x.0;
        let n = &Self::P.0;

        // Compute a * b[0]
        let mut carry1 = 0u64;
        let r0 = mac(a[0], b[0], 0, &mut carry1);
        let r1 = mac(a[1], b[0], 0, &mut carry1);
        let r2 = mac(a[2], b[0], 0, &mut carry1);
        let r3 = mac(a[3], b[0], 0, &mut carry1);

        // Reduce it
        let k = r0.wrapping_mul(Self::M0);
        let mut carry2 = 0u64;
        mac(k, n[0], r0, &mut carry2);
        let r0 = mac(k, n[1], r1, &mut carry2);
        let r1 = mac(k, n[2], r2, &mut carry2);
        let r2 = mac(k, n[3], r3, &mut carry2);
        let r3 = carry1 + carry2;

        // Compute a * b[1]
        let mut carry1 = 0u64;
        let r0 = mac(a[0], b[1], r0, &mut carry1);
        let r1 = mac(a[1], b[1], r1, &mut carry1);
        let r2 = mac(a[2], b[1], r2, &mut carry1);
        let r3 = mac(a[3], b[1], r3, &mut carry1);

        // Reduce it
        let k = r0.wrapping_mul(Self::M0);
        let mut carry2 = 0u64;
        mac(k, n[0], r0, &mut carry2);
        let r0 = mac(k, n[1], r1, &mut carry2);
        let r1 = mac(k, n[2], r2, &mut carry2);
        let r2 = mac(k, n[3], r3, &mut carry2);
        let r3 = carry1 + carry2;

        // Compute a * b[2]
        let mut carry1 = 0u64;
        let r0 = mac(a[0], b[2], r0, &mut carry1);
        let r1 = mac(a[1], b[2], r1, &mut carry1);
        let r2 = mac(a[2], b[2], r2, &mut carry1);
        let r3 = mac(a[3], b[2], r3, &mut carry1);

        // Reduce it
        let k = r0.wrapping_mul(Self::M0);
        let mut carry2 = 0u64;
        mac(k, n[0], r0, &mut carry2);
        let r0 = mac(k, n[1], r1, &mut carry2);
        let r1 = mac(k, n[2], r2, &mut carry2);
        let r2 = mac(k, n[3], r3, &mut carry2);
        let r3 = carry1 + carry2;

        // Compute a * b[3]
        let mut carry1 = 0u64;
        let r0 = mac(a[0], b[3], r0, &mut carry1);
        let r1 = mac(a[1], b[3], r1, &mut carry1);
        let r2 = mac(a[2], b[3], r2, &mut carry1);
        let r3 = mac(a[3], b[3], r3, &mut carry1);

        // Reduce it
        let k = r0.wrapping_mul(Self::M0);
        let mut carry2 = 0u64;
        mac(k, n[0], r0, &mut carry2);
        let r0 = mac(k, n[1], r1, &mut carry2);
        let r1 = mac(k, n[2], r2, &mut carry2);
        let r2 = mac(k, n[3], r3, &mut carry2);
        let r3 = carry1 + carry2;

        // Subtract modulus if needed
        let r = MontFelt([r0, r1, r2, r3]);
        r.reduce_partial()
    }

    /// SOS squaring algorithm
    #[inline(always)]
    pub fn square(&self) -> MontFelt {
        // Compute sum of a[i] * b[j] for i<j
        let mut carry = 0;
        let r1 = mac(self.0[0usize], self.0[1usize], 0, &mut carry);
        let r2 = mac(self.0[0usize], self.0[2usize], 0, &mut carry);
        let r3 = mac(self.0[0usize], self.0[3usize], 0, &mut carry);
        let r4 = carry;

        let mut carry = 0;
        let r3 = mac(self.0[1usize], self.0[2usize], r3, &mut carry);
        let r4 = mac(self.0[1usize], self.0[3usize], r4, &mut carry);
        let r5 = carry;

        let mut carry = 0;
        let r5 = mac(self.0[2usize], self.0[3usize], r5, &mut carry);
        let r6 = carry;

        // Double it
        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        // Add the diagonal a[i] * b[i]
        let mut carry = 0;
        let r0 = mac(self.0[0usize], self.0[0usize], 0, &mut carry);
        let r1 = acc(r1, &mut carry);
        let r2 = mac(self.0[1usize], self.0[1usize], r2, &mut carry);
        let r3 = acc(r3, &mut carry);
        let r4 = mac(self.0[2usize], self.0[2usize], r4, &mut carry);
        let r5 = acc(r5, &mut carry);
        let r6 = mac(self.0[3usize], self.0[3usize], r6, &mut carry);
        let r7 = acc(r7, &mut carry);

        // Montgomery reduction
        MontFelt::mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }
}

impl std::ops::Mul<Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        Self::mul(&self, &rhs)
    }
}

impl std::ops::Mul<&Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: &Self) -> Self::Output {
        Self::mul(&self, rhs)
    }
}

impl std::ops::Mul<&mut Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn mul(self, rhs: &mut Self) -> Self::Output {
        Self::mul(&self, rhs)
    }
}

impl std::ops::MulAssign<Self> for MontFelt {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mul(self, &rhs);
    }
}

impl std::ops::MulAssign<&Self> for MontFelt {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &Self) {
        *self = Self::mul(self, rhs);
    }
}

impl std::ops::MulAssign<&mut Self> for MontFelt {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: &mut Self) {
        *self = Self::mul(self, rhs);
    }
}
