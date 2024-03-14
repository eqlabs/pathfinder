use crate::MontFelt;

impl MontFelt {
    /// Tonelli-Shanks algorithm to compute the square root
    ///
    /// Based on arkwork which is based on <https://eprint.iacr.org/2012/685.pdf> (p.12, alg.5).
    pub fn sqrt(&self) -> Option<MontFelt> {
        if self.is_zero() {
            return Some(MontFelt::ZERO);
        }

        let mut z = MontFelt::from_limbs(MontFelt::SQRT_T);
        let mut w = self.pow(MontFelt::SQRT_T_MINUS_ONE_DIV2);
        let mut x = w * self;
        let mut b = x * w;

        let mut v = MontFelt::SQRT_S;

        while !b.is_one() {
            let mut k = 0;

            let mut b2k = b;
            while !b2k.is_one() {
                b2k = b2k.square();
                k += 1;
            }

            if k == MontFelt::SQRT_S {
                return None;
            }
            let j = v - k;
            w = z;
            for _ in 1..j {
                w = w.square();
            }

            z = w.square();
            b *= z;
            x *= w;
            v = k;
        }

        if x.square() == *self {
            Some(x)
        } else {
            None
        }
    }
}
