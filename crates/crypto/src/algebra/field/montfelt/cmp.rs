use std::cmp::Ordering;

use crate::MontFelt;

impl MontFelt {
    /// Returns whether the value is zero
    #[inline(always)]
    pub const fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Return whether the value is one
    #[inline(always)]
    pub const fn is_one(&self) -> bool {
        self.0[0] == MontFelt::R[0]
            && self.0[1] == MontFelt::R[1]
            && self.0[2] == MontFelt::R[2]
            && self.0[3] == MontFelt::R[3]
    }

    /// Compares two elements' native integer representation
    #[inline(always)]
    pub const fn const_cmp_native(&self, x: &MontFelt) -> Ordering {
        let a = self.const_reduce_full();
        let b = x.const_reduce_full();
        a.const_cmp(&b)
    }

    /// Compare representations
    #[inline(always)]
    pub const fn const_cmp(&self, x: &MontFelt) -> Ordering {
        let mut i = 4;
        while i > 0 {
            i -= 1;
            if self.0[i] < x.0[i] {
                return Ordering::Less;
            } else if self.0[i] > x.0[i] {
                return Ordering::Greater;
            }
        }
        Ordering::Equal
    }

    /// Equality
    #[inline(always)]
    pub const fn const_eq(&self, x: &MontFelt) -> bool {
        self.const_cmp(x) as i8 == 0
    }

    /// Greater than
    #[inline(always)]
    pub const fn const_gt(&self, x: &MontFelt) -> bool {
        self.const_cmp(x) as i8 > 0
    }

    /// Greater than or equal
    #[inline(always)]
    pub const fn const_geq(&self, x: &MontFelt) -> bool {
        self.const_cmp(x) as i8 >= 0
    }

    /// Less than
    #[inline(always)]
    pub const fn const_lt(&self, x: &MontFelt) -> bool {
        (self.const_cmp(x) as i8) < 0
    }

    /// Less than or equal
    #[inline(always)]
    pub const fn const_leq(&self, x: &MontFelt) -> bool {
        self.const_cmp(x) as i8 <= 0
    }
}

impl Ord for MontFelt {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.const_cmp_native(other)
    }
}

impl PartialOrd for MontFelt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ord() {
        let a = MontFelt::ONE;
        let b = MontFelt::ONE + MontFelt::ONE;
        let c = MontFelt::ONE + MontFelt::ONE + MontFelt::ONE;

        assert!(a < b);
        assert!(a <= b);
        assert!(a < c);
        assert!(a <= c);
        assert!(b < c);
        assert!(b <= c);

        assert!(b > a);
        assert!(b >= a);
        assert!(c > a);
        assert!(c >= a);
        assert!(c > b);
        assert!(c >= b);

        assert!(a == a);
        assert!(b == b);
        assert!(c == c);
    }
}
