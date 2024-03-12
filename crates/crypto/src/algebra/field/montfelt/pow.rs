use crate::algebra::field::montfelt::bits::BitIteratorBE;
use crate::MontFelt;

impl MontFelt {
    /// Computes `self^exp` where `exp` is u64 limbs in little-endian, based on arkworks.
    pub(crate) fn pow<S: AsRef<[u64]>>(&self, exp: S) -> Self {
        let mut res = Self::ONE;
        for i in BitIteratorBE::without_leading_zeros(exp) {
            res = res.square();
            if i {
                res *= self;
            }
        }
        res
    }
}
