use crate::MontFelt;

impl MontFelt {
    #[inline(always)]
    #[allow(clippy::comparison_chain)]
    pub fn mont_cmp(&self, x: &MontFelt) -> isize {
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
    pub const fn cmp(&self, x: &MontFelt) -> isize {
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

    pub const fn eq(&self, x: &MontFelt) -> bool {
        self.cmp(x) == 0
    }

    pub const fn gt(&self, x: &MontFelt) -> bool {
        self.cmp(x) > 0
    }

    pub const fn geq(&self, x: &MontFelt) -> bool {
        self.cmp(x) >= 0
    }

    pub const fn lt(&self, x: &MontFelt) -> bool {
        self.cmp(x) < 0
    }

    pub const fn leq(&self, x: &MontFelt) -> bool {
        self.cmp(x) <= 0
    }
}

impl std::cmp::PartialOrd for MontFelt {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match self.mont_cmp(other) {
            1 => Some(std::cmp::Ordering::Greater),
            -1 => Some(std::cmp::Ordering::Less),
            0 => Some(std::cmp::Ordering::Equal),
            _ => None,
        }
    }
}
