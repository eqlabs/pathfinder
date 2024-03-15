use crate::algebra::field::bits::BitIteratorBE;
use crate::MontFelt;

impl MontFelt {
    /// Computes `self^exp` where `exp` is u64 limbs in little-endian.
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
