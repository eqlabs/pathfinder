use crate::CurveOrderMontFelt;
use rand::Rng;

impl CurveOrderMontFelt {
    /// Try to sample a random field element
    pub fn sample<R: Rng>(rng: &mut R) -> Option<Self> {
        let mut s = CurveOrderMontFelt([
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
            rng.gen::<u64>(),
        ]);
        s.0[3] &= 0xffffffffffffffffu64 >> CurveOrderMontFelt::ZERO_BITS;
        if s.lt(&CurveOrderMontFelt::P) {
            Some(s)
        } else {
            None
        }
    }

    /// Rejection sample a random field element
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        loop {
            if let Some(s) = CurveOrderMontFelt::sample(rng) {
                return s;
            }
        }
    }
}
