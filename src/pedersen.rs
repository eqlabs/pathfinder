use ff::{Field, PrimeField};

/// The field primitive used by [PedersenHash]
#[derive(PrimeField)]
#[PrimeFieldModulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "little"]
pub struct H256([u64; 4]);

pub fn pedersen_hash(a: &H256, b: &H256) -> H256 {
    PEDERSEN_HASHER.hash(a, b)
}

lazy_static::lazy_static!(
    static ref PEDERSEN_HASHER: PedersenHash = PedersenHash::default();
);

impl H256 {
    /// Returns the i'th bit. Panic's if `i` is out of bounds.
    fn get_bit(&self, i: usize) -> Bit {
        let mut r = *self;
        r.mont_reduce(
            self.0[0usize],
            self.0[1usize],
            self.0[2usize],
            self.0[3usize],
            0,
            0,
            0,
            0,
        );

        let outer = i / 64;
        let inner = i % 64;

        match (r.0[outer] >> inner) & 0b1 {
            0 => Bit::Zero,
            _ => Bit::One,
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Bit {
    One,
    Zero,
}

impl Bit {
    fn is_one(&self) -> bool {
        *self == Bit::One
    }

    fn is_zero(&self) -> bool {
        !self.is_one()
    }
}

/// A point on an elliptic curve over [H251].
#[derive(Clone, Debug, Eq, PartialEq)]
struct CurvePoint {
    x: H256,
    y: H256,
    infinity: bool,
}

impl CurvePoint {
    fn identity() -> CurvePoint {
        Self {
            x: H256::zero(),
            y: H256::zero(),
            infinity: true,
        }
    }

    fn from_xy_str(x: &str, y: &str) -> CurvePoint {
        let x = H256::from_str_vartime(x).expect("Curve x-value invalid");
        let y = H256::from_str_vartime(y).expect("Curve y-value invalid");

        CurvePoint {
            x,
            y,
            infinity: false,
        }
    }

    fn generator() -> CurvePoint {
        Self::from_xy_str(
            "874739451078007766457464989774322083649278607533249481151382481072868806602",
            "152666792071518830868575557812948353041420400780739481342941381225525861407",
        )
    }

    fn double(&self) -> CurvePoint {
        if self.infinity {
            return self.clone();
        }

        // l = (3x^2+a)/2y with a=1 from stark curve
        let lambda = {
            let two = H256::one() + H256::one();
            let three = two + H256::one();
            let dividend = three * (self.x * self.x) + H256::one();
            let divisor_inv = (two * self.y).invert().unwrap();
            dividend * divisor_inv
        };

        let result_x = (lambda * lambda) - self.x - self.x;
        let result_y = lambda * (self.x - result_x) - self.y;

        CurvePoint {
            x: result_x,
            y: result_y,
            infinity: false,
        }
    }

    fn add(&self, other: &CurvePoint) -> CurvePoint {
        if self.infinity {
            return other.clone();
        }
        if other.infinity {
            return self.clone();
        }

        // l = (y2-y1)/(x2-x1)
        let lambda = {
            let dividend = other.y - self.y;
            let divisor_inv = (other.x - self.x).invert().unwrap();
            dividend * divisor_inv
        };

        let result_x = (lambda * lambda) - self.x - other.x;
        let result_y = lambda * (self.x - result_x) - self.y;

        CurvePoint {
            x: result_x,
            y: result_y,
            infinity: false,
        }
    }

    fn mul(&self, magnitude: &H256) -> CurvePoint {
        let mut result = CurvePoint::identity();
        for i in 0..256 {
            result = result.double();
            if magnitude.get_bit(255 - i).is_one() {
                result = result.add(self);
            }
        }
        result
    }
}

/// Pedersen hasher
#[derive(Clone, Debug)]
struct PedersenHash {
    p0: CurvePoint,
    p1: CurvePoint,
    p2: CurvePoint,
    p3: CurvePoint,
    p4: CurvePoint,
}

impl Default for PedersenHash {
    fn default() -> Self {
        PedersenHash {
            p0: CurvePoint::from_xy_str(
                "2089986280348253421170679821480865132823066470938446095505822317253594081284",
                "1713931329540660377023406109199410414810705867260802078187082345529207694986",
            ),
            p1: CurvePoint::from_xy_str(
                "996781205833008774514500082376783249102396023663454813447423147977397232763",
                "1668503676786377725805489344771023921079126552019160156920634619255970485781",
            ),
            p2: CurvePoint::from_xy_str(
                "2251563274489750535117886426533222435294046428347329203627021249169616184184",
                "1798716007562728905295480679789526322175868328062420237419143593021674992973",
            ),
            p3: CurvePoint::from_xy_str(
                "2138414695194151160943305727036575959195309218611738193261179310511854807447",
                "113410276730064486255102093846540133784865286929052426931474106396135072156",
            ),
            p4: CurvePoint::from_xy_str(
                "2379962749567351885752724891227938183011949129833673362440656643086021394946",
                "776496453633298175483985398648758586525933812536653089401905292063708816422",
            ),
        }
    }
}

impl PedersenHash {
    fn hash(&self, a: &H256, b: &H256) -> H256 {
        // Add P0
        let mut result = self.p0.clone();

        // Add a_low * P1
        let mut tmp = CurvePoint::identity();
        for i in 0..248 {
            tmp = tmp.double();
            if a.get_bit(248 - 1 - i).is_one() {
                tmp = tmp.add(&self.p1);
            }
        }
        result = result.add(&tmp);

        // Add a_high * P2
        let mut tmp = CurvePoint::identity();
        for i in 0..4 {
            tmp = tmp.double();
            if a.get_bit(252 - 1 - i).is_one() {
                tmp = tmp.add(&self.p2);
            }
        }
        result = result.add(&tmp);

        // Add b_low * P3
        let mut tmp = CurvePoint::identity();
        for i in 0..248 {
            tmp = tmp.double();
            if b.get_bit(248 - 1 - i).is_one() {
                tmp = tmp.add(&self.p3);
            }
        }
        result = result.add(&tmp);

        // Add b_high * P4
        let mut tmp = CurvePoint::identity();
        for i in 0..4 {
            tmp = tmp.double();
            if b.get_bit(252 - 1 - i).is_one() {
                tmp = tmp.add(&self.p4);
            }
        }
        result = result.add(&tmp);

        // Return x-coordinate
        result.x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod get_bit {
        use super::*;

        #[test]
        fn zero() {
            let zero = H256::zero();
            for i in 0..=255 {
                assert!(zero.get_bit(i).is_zero(), "bit {}", i);
            }
        }

        #[test]
        fn one() {
            let one = H256::one();
            assert!(one.get_bit(0).is_one());
            for i in 1..=255 {
                assert!(one.get_bit(i).is_zero(), "bit {}", i);
            }
        }

        #[test]
        fn two() {
            let two = H256::one() + H256::one();
            assert!(two.get_bit(0).is_zero());
            assert!(two.get_bit(1).is_one());
            for i in 2..=255 {
                assert!(two.get_bit(i).is_zero(), "bit {}", i);
            }
        }
    }

    mod curve {
        use super::*;

        #[test]
        fn generator() {
            let g = CurvePoint::generator();
            let expected = CurvePoint::from_xy_str(
                "874739451078007766457464989774322083649278607533249481151382481072868806602",
                "152666792071518830868575557812948353041420400780739481342941381225525861407",
            );
            assert_eq!(g, expected);
        }

        #[test]
        fn double() {
            let g_double = CurvePoint::generator().double();
            let expected = CurvePoint::from_xy_str(
                "3324833730090626974525872402899302150520188025637965566623476530814354734325",
                "3147007486456030910661996439995670279305852583596209647900952752170983517249",
            );
            assert_eq!(g_double, expected);
        }

        #[test]
        fn double_and_add() {
            let g = CurvePoint::generator();
            let g_double = g.double();
            let g_triple = g_double.add(&g);
            let expected = CurvePoint::from_xy_str(
                "1839793652349538280924927302501143912227271479439798783640887258675143576352",
                "3564972295958783757568195431080951091358810058262272733141798511604612925062",
            );
            assert_eq!(g_triple, expected);
        }

        #[test]
        fn mul() {
            let three = H256::one() + H256::one() + H256::one();
            let g = CurvePoint::generator();
            let g_triple = g.mul(&three);
            let expected = CurvePoint::from_xy_str(
                "1839793652349538280924927302501143912227271479439798783640887258675143576352",
                "3564972295958783757568195431080951091358810058262272733141798511604612925062",
            );
            assert_eq!(g_triple, expected);
        }
    }

    #[test]
    #[ignore = "we need test data for the pedersen hash"]
    fn hash() {
        todo!("Get test data for pedersen hash");
    }
}
