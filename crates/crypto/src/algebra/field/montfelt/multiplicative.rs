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

    /// SOS multiplication algorithm
    #[inline(always)]
    #[allow(unused)]
    pub fn mul(&self, x: &MontFelt) -> MontFelt {
        // Compute a[0] * b
        let mut carry = 0;
        let r0 = mac(self.0[0], x.0[0], 0, &mut carry);
        let r1 = mac(self.0[0], x.0[1], 0, &mut carry);
        let r2 = mac(self.0[0], x.0[2], 0, &mut carry);
        let r3 = mac(self.0[0], x.0[3], 0, &mut carry);
        let r4 = carry;

        // Compute a[1] * b
        let mut carry = 0;
        let r1 = mac(self.0[1], x.0[0], r1, &mut carry);
        let r2 = mac(self.0[1], x.0[1], r2, &mut carry);
        let r3 = mac(self.0[1], x.0[2], r3, &mut carry);
        let r4 = mac(self.0[1], x.0[3], r4, &mut carry);
        let r5 = carry;

        // Compute a[2] * b
        let mut carry = 0;
        let r2 = mac(self.0[2], x.0[0], r2, &mut carry);
        let r3 = mac(self.0[2], x.0[1], r3, &mut carry);
        let r4 = mac(self.0[2], x.0[2], r4, &mut carry);
        let r5 = mac(self.0[2], x.0[3], r5, &mut carry);
        let r6 = carry;

        // Compute a[3] * b
        let mut carry = 0;
        let r3 = mac(self.0[3], x.0[0], r3, &mut carry);
        let r4 = mac(self.0[3], x.0[1], r4, &mut carry);
        let r5 = mac(self.0[3], x.0[2], r5, &mut carry);
        let r6 = mac(self.0[3], x.0[3], r6, &mut carry);
        let r7 = carry;

        // Montgomery reduction
        MontFelt::mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use num_bigint::BigUint;

    use super::*;

    #[test]
    fn test_mul_random() {
        let mut rng = rand::thread_rng();
        let bn_p = BigUint::from_str(
            "3618502788666131213697322783095070105623107215331596699973092056135872020481",
        )
        .unwrap();
        for _ in 0..1_000 {
            let a = MontFelt::random(&mut rng);
            let b = MontFelt::random(&mut rng);
            let c = a.mul(&b);

            let bn_a = BigUint::from_bytes_be(&a.to_be_bytes());
            let bn_b = BigUint::from_bytes_be(&b.to_be_bytes());
            let bn_c = &bn_a * &bn_b % &bn_p;

            assert_eq!(BigUint::from_bytes_be(&c.to_be_bytes()), bn_c);
        }
    }
}
