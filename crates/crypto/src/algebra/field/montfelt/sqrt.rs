use crate::MontFelt;

impl MontFelt {
    /// Tonelli-Shanks algorithm to compute the square root
    ///
    /// Based on arkwork which is based on <https://eprint.iacr.org/2012/685.pdf> (p.12, alg.5).
    pub fn sqrt(&self) -> Option<MontFelt> {
        if self.is_zero() {
            return Some(MontFelt::ZERO);
        }

        let mut z = MontFelt::SQRT_Z;
        let mut w = self.pow(MontFelt::SQRT_T_MINUS_ONE_DIV2);
        let mut x = w * self;
        let mut b = x * w;

        let mut v = MontFelt::SQRT_S;

        while !b.is_one() {
            let mut k = 0;

            // Search for minimum k such that b^(2^k) = 1
            let mut b2k = b;
            while !b2k.is_one() {
                b2k = b2k.square();
                k += 1;
            }
            // If k = s, then a square root does not exist (QNR)
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

        // A square root always exists, since QNR's were filtered out
        Some(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sqrt_base() {
        // Test sqrt(9) = 3 or -3
        let nine = MontFelt::from(9u64);
        let three = MontFelt::from(3u64);
        let sqrt = nine.sqrt().unwrap();
        assert!(sqrt == three || sqrt == -three);
    }

    #[test]
    fn test_sqrt_random() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let x = MontFelt::random(&mut rng);
            let sqrt = x.sqrt();
            if let Some(sqrt) = sqrt {
                assert_eq!(sqrt.square(), x);
            }
        }
    }
}
