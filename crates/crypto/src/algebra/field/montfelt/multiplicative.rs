use crate::algebra::field::montfelt::core::{adc, mac};
use crate::MontFelt;

impl MontFelt {
    pub const fn const_mul(&self, x: &MontFelt) -> MontFelt {
        let carry = 0;
        let (r0, carry) = mac(self.0[0], x.0[0], 0, carry);
        let (r1, carry) = mac(self.0[0], x.0[1], 0, carry);
        let (r2, carry) = mac(self.0[0], x.0[2], 0, carry);
        let (r3, carry) = mac(self.0[0], x.0[3], 0, carry);
        let r4 = carry;

        let carry = 0;
        let (r1, carry) = mac(self.0[1], x.0[0], r1, carry);
        let (r2, carry) = mac(self.0[1], x.0[1], r2, carry);
        let (r3, carry) = mac(self.0[1], x.0[2], r3, carry);
        let (r4, carry) = mac(self.0[1], x.0[3], r4, carry);
        let r5 = carry;

        let carry = 0;
        let (r2, carry) = mac(self.0[2], x.0[0], r2, carry);
        let (r3, carry) = mac(self.0[2], x.0[1], r3, carry);
        let (r4, carry) = mac(self.0[2], x.0[2], r4, carry);
        let (r5, carry) = mac(self.0[2], x.0[3], r5, carry);
        let r6 = carry;

        let carry = 0;
        let (r3, carry) = mac(self.0[3], x.0[0], r3, carry);
        let (r4, carry) = mac(self.0[3], x.0[1], r4, carry);
        let (r5, carry) = mac(self.0[3], x.0[2], r5, carry);
        let (r6, carry) = mac(self.0[3], x.0[3], r6, carry);
        let r7 = carry;

        MontFelt::mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }

    pub const fn square(&self) -> MontFelt {
        let carry = 0;
        let (r1, carry) = mac(self.0[0usize], self.0[1usize], 0, carry);
        let (r2, carry) = mac(self.0[0usize], self.0[2usize], 0, carry);
        let (r3, carry) = mac(self.0[0usize], self.0[3usize], 0, carry);
        let r4 = carry;

        let carry = 0;
        let (r3, carry) = mac(self.0[1usize], self.0[2usize], r3, carry);
        let (r4, carry) = mac(self.0[1usize], self.0[3usize], r4, carry);
        let r5 = carry;

        let carry = 0;
        let (r5, carry) = mac(self.0[2usize], self.0[3usize], r5, carry);
        let r6 = carry;

        let r7 = r6 >> 63;
        let r6 = (r6 << 1) | (r5 >> 63);
        let r5 = (r5 << 1) | (r4 >> 63);
        let r4 = (r4 << 1) | (r3 >> 63);
        let r3 = (r3 << 1) | (r2 >> 63);
        let r2 = (r2 << 1) | (r1 >> 63);
        let r1 = r1 << 1;

        let (r0, carry) = mac(self.0[0usize], self.0[0usize], 0, 0);
        let (r1, carry) = adc(r1, 0, carry);
        let (r2, carry) = mac(self.0[1usize], self.0[1usize], r2, carry);
        let (r3, carry) = adc(r3, 0, carry);
        let (r4, carry) = mac(self.0[2usize], self.0[2usize], r4, carry);
        let (r5, carry) = adc(r5, 0, carry);
        let (r6, carry) = mac(self.0[3usize], self.0[3usize], r6, carry);
        let (r7, _) = adc(r7, 0, carry);

        MontFelt::mont_reduce(r0, r1, r2, r3, r4, r5, r6, r7)
    }
}

impl std::ops::Mul<Self> for MontFelt {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.const_mul(&rhs)
    }
}

impl std::ops::Mul<&Self> for MontFelt {
    type Output = Self;
    fn mul(self, rhs: &Self) -> Self::Output {
        self.const_mul(rhs)
    }
}

impl std::ops::Mul<&mut Self> for MontFelt {
    type Output = Self;
    fn mul(self, rhs: &mut Self) -> Self::Output {
        self.const_mul(rhs)
    }
}

impl std::ops::MulAssign<Self> for MontFelt {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.const_mul(&rhs);
    }
}

impl std::ops::MulAssign<&Self> for MontFelt {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = self.const_mul(rhs);
    }
}

impl std::ops::MulAssign<&mut Self> for MontFelt {
    fn mul_assign(&mut self, rhs: &mut Self) {
        *self = self.const_mul(rhs);
    }
}
