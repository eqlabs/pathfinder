use crate::MontFelt;

impl MontFelt {
    /// Computes the modular inverse modulo p
    ///
    /// Based on arkworks which is based on "Efficient Software-Implementations
    /// of Finite Fields with Applications to Cryptography" by Guajardo et
    /// al. (2006, alg. 16).
    pub fn inverse(&self) -> Option<MontFelt> {
        if self.is_zero() {
            None
        } else {
            let one = [1u64, 0, 0, 0];

            let mut u = *self;
            let mut v = Self::P;

            let mut b = MontFelt(Self::R2);
            let mut c = Self::ZERO;

            while u.0 != one && v.0 != one {
                while u.is_even() {
                    u = u.div2();
                    if b.is_even() {
                        b = b.div2();
                    } else {
                        b = b.add_noreduce(&Self::P);
                        b = b.div2();
                    }
                }

                while v.is_even() {
                    v = v.div2();
                    if c.is_even() {
                        c = c.div2();
                    } else {
                        c = c.add_noreduce(&Self::P);
                        c = c.div2();
                    }
                }

                if v.const_lt(&u) {
                    u = u.sub_noreduce(&v);
                    b = b.const_sub(&c);
                } else {
                    v = v.sub_noreduce(&u);
                    c = c.const_sub(&b);
                }
            }

            if u.0 == one {
                Some(b)
            } else {
                Some(c)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inverse_base() {
        let x = MontFelt::from_hex("9");
        let inv = x.inverse().unwrap();
        let xinv = x * inv;
        assert_eq!(xinv, MontFelt::ONE);
    }

    #[test]
    fn test_inverse_random() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let x = MontFelt::random(&mut rng);
            let inv = x.inverse().unwrap();
            let xinv = x * inv;
            assert_eq!(xinv, MontFelt::ONE);
        }
    }
}
