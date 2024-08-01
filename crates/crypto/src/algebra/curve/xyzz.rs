use crate::algebra::curve::*;
use crate::algebra::field::*;

/// A XYZZ point on an elliptic curve over [MontFelt] satisfying:
///   x = X / ZZ
///   y = Y / ZZ
///   ZZ^3 = ZZZ^2
///
/// This point representation is used for fast table-based scalar multiplication
/// and only include add_affine and add_affine_unchecked operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XYZZPoint {
    pub x: MontFelt,
    pub y: MontFelt,
    pub zz: MontFelt,
    pub zzz: MontFelt,
}

impl From<&AffinePoint> for XYZZPoint {
    fn from(p: &AffinePoint) -> Self {
        let x = p.x;
        let y = p.y;
        let zz = MontFelt::ONE;
        let zzz = MontFelt::ONE;
        XYZZPoint { x, y, zz, zzz }
    }
}

impl XYZZPoint {
    /// Check if the point is the point of infinity
    pub fn is_infinity(&self) -> bool {
        self.zz.is_zero()
    }

    /// Add an affine point to this point
    pub fn add_affine(&mut self, other: &AffinePoint) {
        if other.infinity {
            return;
        }
        if self.is_infinity() {
            self.x = other.x;
            self.y = other.y;
            let z = if other.infinity {
                MontFelt::ZERO
            } else {
                MontFelt::ONE
            };
            self.zz = z;
            self.zzz = z;

            return;
        }
        self.add_affine_unchecked(other);
    }

    /// Add an affine point to this point, neither must be the point of infinity
    pub fn add_affine_unchecked(&mut self, other: &AffinePoint) {
        // See https://www.hyperelliptic.org/EFD/g1p/auto-shortw-xyzz.html#addition-madd-2008-s
        let p = other.x * self.zz - self.x;
        let r = other.y * self.zzz - self.y;
        let pp = p.square();
        let ppp = p * pp;
        let q = self.x * pp;
        self.x = r.square() - ppp - q.double();
        self.y = r * (q - self.x) - self.y * ppp;
        self.zz *= pp;
        self.zzz *= ppp;
    }
}
