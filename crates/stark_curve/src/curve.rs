use crate::field::FieldElement;
use bitvec::{order::Lsb0, slice::BitSlice};
use ff::Field;

/// An affine point on an elliptic curve over [FieldElement].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub infinity: bool,
}

impl From<&ProjectivePoint> for AffinePoint {
    fn from(p: &ProjectivePoint) -> Self {
        let zinv = p.z.invert().unwrap();
        let x = p.x * zinv;
        let y = p.y * zinv;
        AffinePoint {
            x,
            y,
            infinity: false,
        }
    }
}

impl AffinePoint {
    pub const fn new(x: [u64; 4], y: [u64; 4]) -> Self {
        Self {
            x: FieldElement::new(x),
            y: FieldElement::new(y),
            infinity: false,
        }
    }

    pub fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            infinity: true,
        }
    }

    pub fn double(&mut self) {
        if self.infinity {
            return;
        }

        // l = (3x^2+a)/2y with a=1 from stark curve
        let lambda = {
            let dividend = FieldElement::THREE * (self.x * self.x) + FieldElement::one();
            let divisor_inv = (FieldElement::TWO * self.y).invert().unwrap();
            dividend * divisor_inv
        };

        let result_x = (lambda * lambda) - self.x - self.x;
        self.y = lambda * (self.x - result_x) - self.y;
        self.x = result_x;
    }

    pub fn add(&mut self, other: &AffinePoint) {
        if other.infinity {
            return;
        }
        if self.infinity {
            self.x = other.x;
            self.y = other.y;
            self.infinity = other.infinity;
            return;
        }
        if self.x == other.x {
            if self.y != other.y {
                self.infinity = true;
            } else {
                self.double();
            }
            return;
        }

        // l = (y2-y1)/(x2-x1)
        let lambda = {
            let dividend = other.y - self.y;
            let divisor_inv = (other.x - self.x).invert().unwrap();
            dividend * divisor_inv
        };

        let result_x = (lambda * lambda) - self.x - other.x;
        self.y = lambda * (self.x - result_x) - self.y;
        self.x = result_x;
    }

    pub fn multiply(&self, bits: &BitSlice<Lsb0, u64>) -> AffinePoint {
        let mut product = AffinePoint::identity();
        for b in bits.iter().rev() {
            product.double();
            if *b {
                product.add(self);
            }
        }
        product
    }
}

/// A projective point on an elliptic curve over [FieldElement].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectivePoint {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub infinity: bool,
}

impl From<&AffinePoint> for ProjectivePoint {
    fn from(p: &AffinePoint) -> Self {
        let x = p.x;
        let y = p.y;
        let z = FieldElement::ONE;
        ProjectivePoint {
            x,
            y,
            z,
            infinity: false,
        }
    }
}

impl ProjectivePoint {
    pub fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::zero(),
            z: FieldElement::ONE,
            infinity: true,
        }
    }

    pub fn double(&mut self) {
        if self.infinity {
            return;
        }

        // t=3x^2+az^2 with a=1 from stark curve
        let t = FieldElement::THREE * self.x * self.x + self.z * self.z;
        let u = FieldElement::TWO * self.y * self.z;
        let v = FieldElement::TWO * u * self.x * self.y;
        let w = t * t - FieldElement::TWO * v;

        let uy = u * self.y;

        let x = u * w;
        let y = t * (v - w) - FieldElement::TWO * uy * uy;
        let z = u * u * u;

        self.x = x;
        self.y = y;
        self.z = z;
    }

    pub fn add(&mut self, other: &ProjectivePoint) {
        if other.infinity {
            return;
        }
        if self.infinity {
            self.x = other.x;
            self.y = other.y;
            self.z = other.z;
            self.infinity = other.infinity;
            return;
        }
        let u0 = self.x * other.z;
        let u1 = other.x * self.z;
        let t0 = self.y * other.z;
        let t1 = other.y * self.z;
        if u0 == u1 {
            if t0 != t1 {
                self.infinity = true;
            } else {
                self.double();
            }
            return;
        }

        let t = t0 - t1;
        let u = u0 - u1;
        let u2 = u * u;

        let v = self.z * other.z;
        let w = t * t * v - u2 * (u0 + u1);
        let u3 = u * u2;

        let x = u * w;
        let y = t * (u0 * u2 - w) - t0 * u3;
        let z = u3 * v;

        self.x = x;
        self.y = y;
        self.z = z;
    }

    pub fn add_affine(&mut self, other: &AffinePoint) {
        if other.infinity {
            return;
        }
        if self.infinity {
            self.x = other.x;
            self.y = other.y;
            self.z = FieldElement::ONE;
            self.infinity = other.infinity;
            return;
        }
        let u0 = self.x;
        let u1 = other.x * self.z;
        let t0 = self.y;
        let t1 = other.y * self.z;
        if u0 == u1 {
            if t0 != t1 {
                self.infinity = true;
                return;
            } else {
                self.double();
                return;
            }
        }

        let t = t0 - t1;
        let u = u0 - u1;
        let u2 = u * u;

        let v = self.z;
        let w = t * t * v - u2 * (u0 + u1);
        let u3 = u * u2;

        let x = u * w;
        let y = t * (u0 * u2 - w) - t0 * u3;
        let z = u3 * v;

        self.x = x;
        self.y = y;
        self.z = z;
    }

    pub fn multiply(&self, bits: &BitSlice<Lsb0, u64>) -> ProjectivePoint {
        let mut product = ProjectivePoint::identity();
        for b in bits.iter().rev() {
            product.double();
            if *b {
                product.add(self);
            }
        }
        product
    }
}

/// Montgomery representation of the Stark curve generator G.
#[allow(dead_code)]
pub const CURVE_G: ProjectivePoint = ProjectivePoint {
    x: FieldElement::new([
        14484022957141291997,
        5884444832209845738,
        299981207024966779,
        232005955912912577,
    ]),
    y: FieldElement::new([
        6241159653446987914,
        664812301889158119,
        18147424675297964973,
        405578048423154473,
    ]),
    z: FieldElement::ONE,
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P0.
pub const PEDERSEN_P0: ProjectivePoint = ProjectivePoint {
    x: FieldElement::new([
        1933903796324928314,
        7739989395386261137,
        1641324389046377921,
        316327189671755572,
    ]),
    y: FieldElement::new([
        14252083571674603243,
        12587053260418384210,
        4798858472748676776,
        81375596133053150,
    ]),
    z: FieldElement::ONE,
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P1.
pub const PEDERSEN_P1: ProjectivePoint = ProjectivePoint {
    x: FieldElement::new([
        3602345268353203007,
        13758484295849329960,
        518715844721862878,
        241691544791834578,
    ]),
    y: FieldElement::new([
        13441546676070136227,
        13001553326386915570,
        433857700841878496,
        368891789801938570,
    ]),
    z: FieldElement::ONE,
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P2.
pub const PEDERSEN_P2: ProjectivePoint = ProjectivePoint {
    x: FieldElement::new([
        16491878934996302286,
        12382025591154462459,
        10043949394709899044,
        253000153565733272,
    ]),
    y: FieldElement::new([
        13950428914333633429,
        2545498000137298346,
        5191292837124484988,
        285630633187035523,
    ]),
    z: FieldElement::ONE,
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P3.
pub const PEDERSEN_P3: ProjectivePoint = ProjectivePoint {
    x: FieldElement::new([
        1203723169299412240,
        18195981508842736832,
        12916675983929588442,
        338510149841406402,
    ]),
    y: FieldElement::new([
        12352616181161700245,
        11743524503750604092,
        11088962269971685343,
        161068411212710156,
    ]),
    z: FieldElement::ONE,
    infinity: false,
};

/// Montgomery representation of the Stark curve constant P4.
pub const PEDERSEN_P4: ProjectivePoint = ProjectivePoint {
    x: FieldElement::new([
        1145636535101238356,
        10664803185694787051,
        299781701614706065,
        425493972656615276,
    ]),
    y: FieldElement::new([
        8187986478389849302,
        4428713245976508844,
        6033691581221864148,
        345457391846365716,
    ]),
    z: FieldElement::ONE,
    infinity: false,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use pretty_assertions::assert_eq;

    fn affine_from_xy_str(x: &str, y: &str) -> AffinePoint {
        let x = FieldElement::from_str_vartime(x).expect("Curve x-value invalid");
        let y = FieldElement::from_str_vartime(y).expect("Curve y-value invalid");
        AffinePoint {
            x,
            y,
            infinity: false,
        }
    }

    fn projective_from_xy_str(x: &str, y: &str) -> ProjectivePoint {
        let x = FieldElement::from_str_vartime(x).expect("Curve x-value invalid");
        let y = FieldElement::from_str_vartime(y).expect("Curve y-value invalid");
        ProjectivePoint {
            x,
            y,
            z: FieldElement::ONE,
            infinity: false,
        }
    }

    #[test]
    fn projective_double() {
        let g_double = {
            let mut g = CURVE_G;
            g.double();
            AffinePoint::from(&g)
        };
        let expected = affine_from_xy_str(
            "3324833730090626974525872402899302150520188025637965566623476530814354734325",
            "3147007486456030910661996439995670279305852583596209647900952752170983517249",
        );
        assert_eq!(g_double, expected);
    }

    #[test]
    fn projective_double_and_add() {
        let g_triple = {
            let mut g = CURVE_G;
            g.double();
            g.add(&CURVE_G);
            AffinePoint::from(&g)
        };
        let expected = affine_from_xy_str(
            "1839793652349538280924927302501143912227271479439798783640887258675143576352",
            "3564972295958783757568195431080951091358810058262272733141798511604612925062",
        );
        assert_eq!(g_triple, expected);
    }

    #[test]
    fn projective_multiply() {
        let three = FieldElement::THREE.into_bits();
        let g = CURVE_G;
        let g_triple = AffinePoint::from(&g.multiply(&three));
        let expected = affine_from_xy_str(
            "1839793652349538280924927302501143912227271479439798783640887258675143576352",
            "3564972295958783757568195431080951091358810058262272733141798511604612925062",
        );
        assert_eq!(g_triple, expected);
    }

    #[test]
    fn affine_projective_multiply() {
        let three = FieldElement::THREE.into_bits();

        let ag = AffinePoint::from(&CURVE_G);
        let ag_triple = ag.multiply(&three);

        let pg = ProjectivePoint::from(&ag);
        let pg_triple = pg.multiply(&three);

        let result = AffinePoint::from(&pg_triple);
        assert_eq!(ag_triple.x, result.x);
    }

    #[test]
    fn const_generator() {
        let expected = projective_from_xy_str(
            "874739451078007766457464989774322083649278607533249481151382481072868806602",
            "152666792071518830868575557812948353041420400780739481342941381225525861407",
        );
        assert_eq!(CURVE_G, expected);
    }

    #[test]
    fn const_p0() {
        let expected = projective_from_xy_str(
            "2089986280348253421170679821480865132823066470938446095505822317253594081284",
            "1713931329540660377023406109199410414810705867260802078187082345529207694986",
        );
        assert_eq!(PEDERSEN_P0, expected);
    }

    #[test]
    fn const_p1() {
        let expected = projective_from_xy_str(
            "996781205833008774514500082376783249102396023663454813447423147977397232763",
            "1668503676786377725805489344771023921079126552019160156920634619255970485781",
        );
        assert_eq!(PEDERSEN_P1, expected);
    }

    #[test]
    fn const_p2() {
        let expected = projective_from_xy_str(
            "2251563274489750535117886426533222435294046428347329203627021249169616184184",
            "1798716007562728905295480679789526322175868328062420237419143593021674992973",
        );
        assert_eq!(PEDERSEN_P2, expected);
    }

    #[test]
    fn const_p3() {
        let expected = projective_from_xy_str(
            "2138414695194151160943305727036575959195309218611738193261179310511854807447",
            "113410276730064486255102093846540133784865286929052426931474106396135072156",
        );
        assert_eq!(PEDERSEN_P3, expected);
    }

    #[test]
    fn const_p4() {
        let expected = projective_from_xy_str(
            "2379962749567351885752724891227938183011949129833673362440656643086021394946",
            "776496453633298175483985398648758586525933812536653089401905292063708816422",
        );
        assert_eq!(PEDERSEN_P4, expected);
    }
}
