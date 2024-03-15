use crate::MontFelt;

impl MontFelt {
    #[inline(always)]
    pub const fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    #[inline(always)]
    pub const fn is_even(&self) -> bool {
        self.0[0] & 1 == 0
    }
}
