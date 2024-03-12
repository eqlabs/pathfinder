use crate::MontFelt;

impl MontFelt {
    pub const fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    pub const fn is_even(&self) -> bool {
        self.0[0] & 1 == 0
    }
}
