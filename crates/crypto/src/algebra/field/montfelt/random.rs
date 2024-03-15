use crate::MontFelt;
use rand::Rng;

impl MontFelt {
    /// Try to sample a random field element
    pub fn sample<R: Rng>(rng: &mut R) -> Option<Self> {
        let mut s = MontFelt([
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
        ]);
        s.0[3] &= 0xffffffffffffffffu64 >> MontFelt::ZERO_BITS;
        if s.lt(&MontFelt::P) {
            Some(s)
        } else {
            None
        }
    }

    /// Rejection sample a random field element
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        loop {
            if let Some(s) = MontFelt::sample(rng) {
                return s;
            }
        }
    }
}
