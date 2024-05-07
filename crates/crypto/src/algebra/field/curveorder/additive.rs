use crate::algebra::field::core::{const_adc, const_sbb};
use crate::CurveOrderMontFelt;

impl CurveOrderMontFelt {
    /// Add two big-integers without reducing modulo p
    #[inline(always)]
    pub const fn add_noreduce(&self, x: &CurveOrderMontFelt) -> CurveOrderMontFelt {
        let mut carry = 0u64;
        let mut res = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            let (lo, hi) = const_adc(self.0[i], x.0[i], carry);
            res[i] = lo;
            carry = hi;
            i += 1;
        }
        CurveOrderMontFelt(res)
    }

    /// Subtract two big-integers without reducing modulo p
    #[inline(always)]
    pub const fn sub_noreduce(&self, x: &CurveOrderMontFelt) -> CurveOrderMontFelt {
        let mut borrow = 0u64;
        let mut res = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            let (lo, hi) = const_sbb(self.0[i], x.0[i], borrow);
            res[i] = lo;
            borrow = hi;
            i += 1;
        }
        CurveOrderMontFelt(res)
    }

    /// Add two field elements
    #[inline(always)]
    pub const fn const_add(&self, x: &CurveOrderMontFelt) -> CurveOrderMontFelt {
        let res = self.add_noreduce(x);
        res.reduce_partial()
    }

    /// Subtract two field elements
    #[inline(always)]
    pub const fn const_sub(&self, x: &CurveOrderMontFelt) -> CurveOrderMontFelt {
        if x.gt(self) {
            let tmp = self.add_noreduce(&CurveOrderMontFelt::P);
            tmp.sub_noreduce(x)
        } else {
            self.sub_noreduce(x)
        }
    }

    /// Negate a field element
    #[inline(always)]
    pub const fn const_neg(&self) -> CurveOrderMontFelt {
        if self.is_zero() {
            *self
        } else {
            CurveOrderMontFelt::P.sub_noreduce(self)
        }
    }

    /// Double a field element
    #[inline(always)]
    pub const fn double(&self) -> CurveOrderMontFelt {
        self.const_add(self)
    }
}

impl std::ops::Add<Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        self.const_add(&rhs)
    }
}

impl std::ops::Add<&Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: &Self) -> Self::Output {
        self.const_add(rhs)
    }
}

impl std::ops::Add<&mut Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn add(self, rhs: &mut Self) -> Self::Output {
        self.const_add(rhs)
    }
}

impl std::ops::AddAssign<Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = self.const_add(&rhs);
    }
}

impl std::ops::AddAssign<&Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &Self) {
        *self = self.const_add(rhs);
    }
}

impl std::ops::AddAssign<&mut Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn add_assign(&mut self, rhs: &mut Self) {
        *self = self.const_add(rhs);
    }
}

impl std::ops::Sub<Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        self.const_sub(&rhs)
    }
}

impl std::ops::Sub<&Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: &Self) -> Self::Output {
        self.const_sub(rhs)
    }
}

impl std::ops::Sub<&mut Self> for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn sub(self, rhs: &mut Self) -> Self::Output {
        self.const_sub(rhs)
    }
}

impl std::ops::SubAssign<Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.const_sub(&rhs);
    }
}

impl std::ops::SubAssign<&Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &Self) {
        *self = self.const_sub(rhs);
    }
}

impl std::ops::SubAssign<&mut Self> for CurveOrderMontFelt {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: &mut Self) {
        *self = self.const_sub(rhs);
    }
}

impl std::ops::Neg for CurveOrderMontFelt {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self::Output {
        self.const_neg()
    }
}

impl std::ops::Neg for &CurveOrderMontFelt {
    type Output = CurveOrderMontFelt;
    #[inline(always)]
    fn neg(self) -> Self::Output {
        self.const_neg()
    }
}

impl std::ops::Neg for &mut CurveOrderMontFelt {
    type Output = CurveOrderMontFelt;
    #[inline(always)]
    fn neg(self) -> Self::Output {
        self.const_neg()
    }
}
