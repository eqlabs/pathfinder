use bitvec::order::Lsb0;
use bitvec::slice::BitSlice;

use crate::algebra::curve::*;
use crate::algebra::field::*;

/// A projective point on an elliptic curve over [MontFelt].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectivePoint {
    pub x: MontFelt,
    pub y: MontFelt,
    pub z: MontFelt,
    pub infinity: bool,
}

impl From<&AffinePoint> for ProjectivePoint {
    fn from(p: &AffinePoint) -> Self {
        let x = p.x;
        let y = p.y;
        let z = MontFelt::ONE;
        ProjectivePoint {
            x,
            y,
            z,
            infinity: false,
        }
    }
}

impl ProjectivePoint {
    /// Create a point from (x,y) as raw u64's in Montgomery representation
    pub const fn from_raw(x: [u64; 4], y: [u64; 4]) -> Self {
        let x = MontFelt::from_raw(x);
        let y = MontFelt::from_raw(y);
        Self {
            x,
            y,
            z: MontFelt::ONE,
            infinity: false,
        }
    }

    /// Create a point from (x,y) in hexadecimal
    pub const fn from_hex(x: &str, y: &str) -> Self {
        let x = MontFelt::from_hex(x);
        let y = MontFelt::from_hex(y);
        Self {
            x,
            y,
            z: MontFelt::ONE,
            infinity: false,
        }
    }

    /// Create a point from the x-coordinate.
    pub fn from_x(x: MontFelt) -> Option<Self> {
        let ap = AffinePoint::from_x(x)?;
        Some(ProjectivePoint::from(&ap))
    }

    /// Point of infinity
    pub fn identity() -> Self {
        Self {
            x: MontFelt::ZERO,
            y: MontFelt::ZERO,
            z: MontFelt::ONE,
            infinity: true,
        }
    }

    /// Negates a point
    pub fn negate(&mut self) {
        self.y = -self.y;
    }

    /// Double a point
    pub fn double(&mut self) {
        if self.infinity {
            return;
        }

        // t=3x^2+az^2 with a=1 from stark curve
        let x2 = self.x.square();
        let t = x2 + x2.double() + self.z.square();
        let u = (self.y * self.z).double();
        let v = (u * self.x * self.y).double();
        let w = t.square() - v.double();

        let uy = u * self.y;

        let x = u * w;
        let y = t * (v - w) - (uy * uy).double();
        let z = u * u * u;

        self.x = x;
        self.y = y;
        self.z = z;
    }

    /// Add a point to this point
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
        let u2 = u.square();

        let v = self.z * other.z;
        let w = t.square() * v - u2 * (u0 + u1);
        let u3 = u * u2;

        let x = u * w;
        let y = t * (u0 * u2 - w) - t0 * u3;
        let z = u3 * v;

        self.x = x;
        self.y = y;
        self.z = z;
    }

    /// Add an affine point to this point
    pub fn add_affine(&mut self, other: &AffinePoint) {
        if other.infinity {
            return;
        }
        if self.infinity {
            self.x = other.x;
            self.y = other.y;
            self.z = MontFelt::ONE;
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

    /// Multiply a point by a bit-representation in LSB order
    pub fn multiply(&self, bits: &BitSlice<u64, Lsb0>) -> ProjectivePoint {
        let mut product = ProjectivePoint::identity();
        for b in bits.iter().rev() {
            product.double();
            if *b {
                product.add(self);
            }
        }
        product
    }

    /// Multiply a point by a curve order field element
    pub fn multiply_elm(&self, elm: &CurveOrderMontFelt) -> ProjectivePoint {
        let bits = elm.into_le_bits();
        self.multiply(bits.as_bitslice())
    }
}
