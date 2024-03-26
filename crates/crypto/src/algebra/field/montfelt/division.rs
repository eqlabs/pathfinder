use crate::MontFelt;

impl MontFelt {
    /// Divides a big-integer by 2, aka shift it one bit to the right
    pub const fn div2(&self) -> MontFelt {
        let r0 = (self.0[0] >> 1) | (self.0[1] << 63);
        let r1 = (self.0[1] >> 1) | (self.0[2] << 63);
        let r2 = (self.0[2] >> 1) | (self.0[3] << 63);
        let r3 = self.0[3] >> 1;
        MontFelt([r0, r1, r2, r3])
    }
}
