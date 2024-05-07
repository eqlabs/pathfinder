use crate::algebra::field::core::{adc, const_adc, const_sbb, sbb};
use crate::MontFelt;

impl MontFelt {
    /// Add two big-integers without reducing modulo p
    #[inline(always)]
    pub const fn const_add_noreduce(&self, x: &MontFelt) -> MontFelt {
        let mut r = MontFelt([0u64; 4]);
        let mut carry = 0u64;
        let mut i = 0;
        while i < 4 {
            let (lo, hi) = const_adc(self.0[i], x.0[i], carry);
            r.0[i] = lo;
            carry = hi;
            i += 1;
        }
        r
    }

    /// Subtract two big-integers without reducing modulo p
    #[inline(always)]
    pub const fn const_sub_noreduce(&self, x: &MontFelt) -> MontFelt {
        let mut r = MontFelt([0u64; 4]);
        let mut borrow = 0u64;
        let mut i = 0;
        while i < 4 {
            let (lo, hi) = const_sbb(self.0[i], x.0[i], borrow);
            r.0[i] = lo;
            borrow = hi;
            i += 1;
        }
        r
    }

    /// Negate a field element
    #[inline(always)]
    pub const fn const_neg(&self) -> MontFelt {
        if self.is_zero() {
            *self
        } else {
            MontFelt::P.const_sub_noreduce(self)
        }
    }

    /// Double a field element
    #[inline(always)]
    pub const fn const_double(&self) -> MontFelt {
        let res = self.const_add_noreduce(self);
        res.const_reduce_partial()
    }

    /// Add two field elements
    #[inline(always)]
    pub const fn const_add(&self, x: &MontFelt) -> MontFelt {
        let res = self.const_add_noreduce(x);
        res.const_reduce_partial()
    }

    /// Subtract two field elements
    #[inline(always)]
    pub const fn const_sub(&self, x: &MontFelt) -> MontFelt {
        if x.const_gt(self) {
            let tmp = self.const_add_noreduce(&MontFelt::P);
            tmp.const_sub_noreduce(x)
        } else {
            self.const_sub_noreduce(x)
        }
    }

    /// Double a field element without reducing modulo p
    #[inline(always)]
    pub fn double_assign_noreduce(&mut self) {
        let mut carry = 0;
        for i in 0..4 {
            let b = self.0[i];
            carry = adc(&mut self.0[i], b, carry);
        }
    }

    /// Add two field elements without reducing modulo p
    #[inline(always)]
    pub fn add_assign_noreduce(&mut self, x: &MontFelt) {
        let mut carry = 0;
        for i in 0..4 {
            carry = adc(&mut self.0[i], x.0[i], carry);
        }
    }

    /// Add two field elements without reducing modulo p
    #[inline(always)]
    pub fn add_noreduce(mut self, x: &MontFelt) -> MontFelt {
        self.add_assign_noreduce(x);
        self
    }

    /// Subtract two field elements without reducing modulo p
    #[inline(always)]
    pub fn sub_assign_noreduce(&mut self, x: &MontFelt) {
        let mut borrow = 0;
        for i in 0..4 {
            borrow = sbb(&mut self.0[i], x.0[i], borrow);
        }
    }

    /// Subtract two field elements without reducing modulo p
    #[inline(always)]
    pub fn sub_noreduce(mut self, x: &MontFelt) -> MontFelt {
        self.sub_assign_noreduce(x);
        self
    }

    /// Negate a field element
    #[inline(always)]
    pub fn negate_assign(&mut self) {
        if !self.is_zero() {
            *self = MontFelt::P.sub_noreduce(self)
        }
    }

    /// Negate a field element
    #[inline(always)]
    pub fn negate(mut self) -> MontFelt {
        self.negate_assign();
        self
    }

    /// Double a field element
    #[inline(always)]
    pub fn double_assign(&mut self) {
        self.double_assign_noreduce();
        self.reduce_partial_assign()
    }

    /// Double a field element
    #[inline(always)]
    pub fn double(mut self) -> MontFelt {
        self.double_assign();
        self
    }

    /// Add two field elements
    #[inline(always)]
    pub fn add_assign(&mut self, x: &MontFelt) {
        self.add_assign_noreduce(x);
        self.reduce_partial_assign()
    }

    /// Add two field elements
    #[inline(always)]
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, x: &MontFelt) -> MontFelt {
        self.add_assign(x);
        self
    }

    /// Subtract two field elements
    #[inline(always)]
    pub fn sub_assign(&mut self, x: &MontFelt) {
        if x.const_gt(self) {
            self.add_assign_noreduce(&MontFelt::P);
        }
        self.sub_assign_noreduce(x)
    }

    /// Subtract two field elements
    #[inline(always)]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(mut self, x: &MontFelt) -> MontFelt {
        self.sub_assign(x);
        self
    }
}

impl std::ops::Add<Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        Self::add(self, &rhs)
    }
}

impl std::ops::Add<&Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        Self::add(self, rhs)
    }
}

impl std::ops::Add<&mut Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: &mut Self) -> Self::Output {
        Self::add(self, rhs)
    }
}

impl std::ops::AddAssign<Self> for MontFelt {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        Self::add_assign(self, &rhs);
    }
}

impl std::ops::AddAssign<&Self> for MontFelt {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        Self::add_assign(self, rhs);
    }
}

impl std::ops::AddAssign<&mut Self> for MontFelt {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &mut Self) {
        Self::add_assign(self, rhs);
    }
}

impl std::ops::Sub<Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        Self::sub(self, &rhs)
    }
}

impl std::ops::Sub<&Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        Self::sub(self, rhs)
    }
}

impl std::ops::Sub<&mut Self> for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: &mut Self) -> Self::Output {
        Self::sub(self, rhs)
    }
}

impl std::ops::SubAssign<Self> for MontFelt {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        Self::sub_assign(self, &rhs);
    }
}

impl std::ops::SubAssign<&Self> for MontFelt {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        Self::sub_assign(self, rhs);
    }
}

impl std::ops::SubAssign<&mut Self> for MontFelt {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &mut Self) {
        Self::sub_assign(self, rhs);
    }
}

impl std::ops::Neg for MontFelt {
    type Output = Self;
    #[inline(always)]
    fn neg(mut self) -> Self::Output {
        self.negate_assign();
        self
    }
}

impl std::ops::Neg for &MontFelt {
    type Output = MontFelt;
    #[inline(always)]
    fn neg(self) -> Self::Output {
        self.negate()
    }
}

impl std::ops::Neg for &mut MontFelt {
    type Output = MontFelt;
    #[inline(always)]
    fn neg(self) -> Self::Output {
        self.negate()
    }
}

#[cfg(test)]
mod tests {
    use super::MontFelt;

    #[test]
    fn test_neg_add_sub_base() {
        // Test -0 = 0
        assert_eq!(-MontFelt::ZERO, MontFelt::ZERO);

        // Test -(-1) = 1
        assert_eq!(-(-MontFelt::ONE), MontFelt::ONE);

        // Test 1 - 1 = 0
        assert_eq!(MontFelt::ONE - MontFelt::ONE, MontFelt::ZERO);

        // Test -1 + 1 = 0
        assert_eq!((-MontFelt::ONE) + MontFelt::ONE, MontFelt::ZERO);

        // Test addition without overflow
        let a = MontFelt([1, 2, 3, 4]);
        let b = MontFelt([5, 6, 7, 8]);
        let c = a + b;
        assert_eq!(c, MontFelt([6, 8, 10, 12]));

        // Test addition with overflow, -1 + 2 = 1
        let one = MontFelt([1, 0, 0, 0]);
        let two = MontFelt([2, 0, 0, 0]);
        let p_minus_one = MontFelt::P.sub_noreduce(&one);
        assert_eq!(p_minus_one + two, one);

        // Test subtraction with overflow, 1 - (p-1) = 1 - (-1) = 2
        assert_eq!(one - p_minus_one, two);
    }

    #[test]
    fn test_add_sub_random() {
        // Tests `a + b - b = a` and `a - b + b = a`
        let rng = &mut rand::thread_rng();
        for _ in 0..1000 {
            let a = MontFelt::random(rng);
            let b = MontFelt::random(rng);
            let c = a + b;
            let d = a - b;
            assert_eq!(a, c - b);
            assert_eq!(a, d + b);
        }
    }
}
