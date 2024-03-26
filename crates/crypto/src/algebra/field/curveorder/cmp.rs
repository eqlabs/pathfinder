use crate::CurveOrderMontFelt;

impl CurveOrderMontFelt {
    /// Return whether the value is zero
    #[inline(always)]
    pub const fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Return whether the value is one
    #[inline(always)]
    pub const fn is_one(&self) -> bool {
        self.0[0] == CurveOrderMontFelt::R[0]
            && self.0[1] == CurveOrderMontFelt::R[1]
            && self.0[2] == CurveOrderMontFelt::R[2]
            && self.0[3] == CurveOrderMontFelt::R[3]
    }

    #[inline(always)]
    #[allow(clippy::comparison_chain)]
    pub fn mont_cmp(&self, x: &CurveOrderMontFelt) -> isize {
        let a = self.reduce_full();
        let b = x.reduce_full();

        let mut i = 4;
        while i > 0 {
            i -= 1;
            if a.0[i] > b.0[i] {
                return 1;
            } else if a.0[i] < b.0[i] {
                return -1;
            }
        }
        0
    }

    #[inline(always)]
    pub const fn cmp(&self, x: &CurveOrderMontFelt) -> isize {
        let mut i = 4;
        while i > 0 {
            i -= 1;
            if self.0[i] > x.0[i] {
                return 1;
            } else if self.0[i] < x.0[i] {
                return -1;
            }
        }
        0
    }

    #[inline(always)]
    pub const fn eq(&self, x: &CurveOrderMontFelt) -> bool {
        self.cmp(x) == 0
    }

    #[inline(always)]
    pub const fn gt(&self, x: &CurveOrderMontFelt) -> bool {
        self.cmp(x) > 0
    }

    #[inline(always)]
    pub const fn geq(&self, x: &CurveOrderMontFelt) -> bool {
        self.cmp(x) >= 0
    }

    #[inline(always)]
    pub const fn lt(&self, x: &CurveOrderMontFelt) -> bool {
        self.cmp(x) < 0
    }

    #[inline(always)]
    pub const fn leq(&self, x: &CurveOrderMontFelt) -> bool {
        self.cmp(x) <= 0
    }
}

impl std::cmp::PartialOrd for CurveOrderMontFelt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.mont_cmp(other) {
            1 => Some(std::cmp::Ordering::Greater),
            -1 => Some(std::cmp::Ordering::Less),
            0 => Some(std::cmp::Ordering::Equal),
            _ => None,
        }
    }
}
