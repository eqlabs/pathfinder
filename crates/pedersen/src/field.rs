use bitvec::{array::BitArray, order::Lsb0, slice::BitSlice};
use ff::{Field, PrimeField};

/// The field primitive used by [PedersenHash]
#[derive(PrimeField)]
#[PrimeFieldModulus = "3618502788666131213697322783095070105623107215331596699973092056135872020481"]
#[PrimeFieldGenerator = "7"]
#[PrimeFieldReprEndianness = "big"]
pub struct FieldElement([u64; 4]);

impl FieldElement {
    /// Transforms [FieldElement] into little endian bit representation.
    pub fn into_bits(mut self) -> BitArray<Lsb0, [u64; 4]> {
        #[cfg(not(target_endian = "little"))]
        {
            todo!("untested and probably unimplemented: big-endian targets")
        }

        #[cfg(target_endian = "little")]
        {
            self.mont_reduce(
                self.0[0usize],
                self.0[1usize],
                self.0[2usize],
                self.0[3usize],
                0,
                0,
                0,
                0,
            );

            self.0.into()
        }
    }
}

/// A point on an elliptic curve over [FieldElement].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurvePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub infinity: bool,
}

impl CurvePoint {
    fn identity() -> CurvePoint {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: true,
        }
    }

    fn double(&self) -> CurvePoint {
        if self.infinity {
            return self.clone();
        }

        // l = (3x^2+a)/2y with a=1 from stark curve
        let lambda = {
            let two = FieldElement::one() + FieldElement::one();
            let three = two + FieldElement::one();
            let dividend = three * (self.x * self.x) + FieldElement::one();
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

    pub fn add(&self, other: &CurvePoint) -> CurvePoint {
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

    pub fn multiply(&self, bits: &BitSlice<Lsb0, u64>) -> CurvePoint {
        let mut product = CurvePoint::identity();
        for b in bits.iter().rev() {
            product = product.double();
            if *b {
                product = product.add(self);
            }
        }

        product
    }
}

/// Montgomery representation of the Stark curve constant P0.
pub const PEDERSEN_P0: CurvePoint = CurvePoint {
    x: FieldElement([
        1933903796324928314,
        7739989395386261137,
        1641324389046377921,
        316327189671755572,
    ]),
    y: FieldElement([
        14252083571674603243,
        12587053260418384210,
        4798858472748676776,
        81375596133053150,
    ]),
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P1.
pub const PEDERSEN_P1: CurvePoint = CurvePoint {
    x: FieldElement([
        3602345268353203007,
        13758484295849329960,
        518715844721862878,
        241691544791834578,
    ]),
    y: FieldElement([
        13441546676070136227,
        13001553326386915570,
        433857700841878496,
        368891789801938570,
    ]),
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P2.
pub const PEDERSEN_P2: CurvePoint = CurvePoint {
    x: FieldElement([
        16491878934996302286,
        12382025591154462459,
        10043949394709899044,
        253000153565733272,
    ]),
    y: FieldElement([
        13950428914333633429,
        2545498000137298346,
        5191292837124484988,
        285630633187035523,
    ]),
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P3.
pub const PEDERSEN_P3: CurvePoint = CurvePoint {
    x: FieldElement([
        1203723169299412240,
        18195981508842736832,
        12916675983929588442,
        338510149841406402,
    ]),
    y: FieldElement([
        12352616181161700245,
        11743524503750604092,
        11088962269971685343,
        161068411212710156,
    ]),
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P4.
pub const PEDERSEN_P4: CurvePoint = CurvePoint {
    x: FieldElement([
        1145636535101238356,
        10664803185694787051,
        299781701614706065,
        425493972656615276,
    ]),
    y: FieldElement([
        8187986478389849302,
        4428713245976508844,
        6033691581221864148,
        345457391846365716,
    ]),
    infinity: false,
};

#[cfg(test)]
mod tests {
    use super::*;

    mod to_le_bits_rev {
        use super::*;
        use pretty_assertions::assert_eq;

        #[test]
        fn zero() {
            let zero = FieldElement::zero().into_bits();
            let expected = BitArray::<Lsb0, [u64; 4]>::default();

            assert_eq!(zero, expected);
        }

        #[test]
        fn one() {
            let one = FieldElement::one().into_bits();

            let mut expected = BitArray::<Lsb0, [u64; 4]>::default();
            expected.set(0, true);

            assert_eq!(one, expected);
        }

        #[test]
        fn two() {
            let two = (FieldElement::one() + FieldElement::one()).into_bits();

            let mut expected = BitArray::<Lsb0, [u64; 4]>::default();
            expected.set(1, true);

            assert_eq!(two, expected);
        }
    }

    mod curve {
        use super::*;
        use pretty_assertions::assert_eq;

        fn curve_from_xy_str(x: &str, y: &str) -> CurvePoint {
            let x = FieldElement::from_str_vartime(x).expect("Curve x-value invalid");
            let y = FieldElement::from_str_vartime(y).expect("Curve y-value invalid");
            CurvePoint {
                x,
                y,
                infinity: false,
            }
        }

        fn curve_generator() -> CurvePoint {
            curve_from_xy_str(
                "874739451078007766457464989774322083649278607533249481151382481072868806602",
                "152666792071518830868575557812948353041420400780739481342941381225525861407",
            )
        }

        #[test]
        fn double() {
            let g_double = curve_generator().double();
            let expected = curve_from_xy_str(
                "3324833730090626974525872402899302150520188025637965566623476530814354734325",
                "3147007486456030910661996439995670279305852583596209647900952752170983517249",
            );
            assert_eq!(g_double, expected);
        }

        #[test]
        fn double_and_add() {
            let g = curve_generator();
            let g_double = g.double();
            let g_triple = g_double.add(&g);
            let expected = curve_from_xy_str(
                "1839793652349538280924927302501143912227271479439798783640887258675143576352",
                "3564972295958783757568195431080951091358810058262272733141798511604612925062",
            );
            assert_eq!(g_triple, expected);
        }

        #[test]
        fn multiply() {
            let three =
                (FieldElement::one() + FieldElement::one() + FieldElement::one()).into_bits();
            let g = curve_generator();
            let g_triple = g.multiply(&three);
            let expected = curve_from_xy_str(
                "1839793652349538280924927302501143912227271479439798783640887258675143576352",
                "3564972295958783757568195431080951091358810058262272733141798511604612925062",
            );
            assert_eq!(g_triple, expected);
        }

        #[test]
        fn p0() {
            let expected = curve_from_xy_str(
                "2089986280348253421170679821480865132823066470938446095505822317253594081284",
                "1713931329540660377023406109199410414810705867260802078187082345529207694986",
            );

            assert_eq!(PEDERSEN_P0, expected);
        }

        #[test]
        fn p1() {
            let expected = curve_from_xy_str(
                "996781205833008774514500082376783249102396023663454813447423147977397232763",
                "1668503676786377725805489344771023921079126552019160156920634619255970485781",
            );

            assert_eq!(PEDERSEN_P1, expected);
        }

        #[test]
        fn p2() {
            let expected = curve_from_xy_str(
                "2251563274489750535117886426533222435294046428347329203627021249169616184184",
                "1798716007562728905295480679789526322175868328062420237419143593021674992973",
            );

            assert_eq!(PEDERSEN_P2, expected);
        }

        #[test]
        fn p3() {
            let expected = curve_from_xy_str(
                "2138414695194151160943305727036575959195309218611738193261179310511854807447",
                "113410276730064486255102093846540133784865286929052426931474106396135072156",
            );

            assert_eq!(PEDERSEN_P3, expected);
        }

        #[test]
        fn p4() {
            let expected = curve_from_xy_str(
                "2379962749567351885752724891227938183011949129833673362440656643086021394946",
                "776496453633298175483985398648758586525933812536653089401905292063708816422",
            );

            assert_eq!(PEDERSEN_P4, expected);
        }
    }
}
