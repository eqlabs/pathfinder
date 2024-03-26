use bitvec::{order::Lsb0, slice::BitSlice};

use crate::algebra::curve::*;
use crate::algebra::field::MontFelt;

/// An affine point on an elliptic curve over the base field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AffinePoint {
    pub x: MontFelt,
    pub y: MontFelt,
    pub infinity: bool,
}

impl From<&ProjectivePoint> for AffinePoint {
    fn from(p: &ProjectivePoint) -> Self {
        let zinv = p.z.inverse().unwrap();
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
    /// Create a point from (x,y) as raw u64's in Montgomery representation
    pub const fn from_raw(x: [u64; 4], y: [u64; 4]) -> Self {
        let x = MontFelt::from_raw(x);
        let y = MontFelt::from_raw(y);
        Self {
            x,
            y,
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
            infinity: false,
        }
    }

    /// Create a point from the x-coordinate.
    pub fn from_x(x: MontFelt) -> Option<Self> {
        // Compute y from curve equation: y^2=x^3+ax+b
        let y2 = x.square() * x + CURVE_A * x + CURVE_B;
        y2.sqrt().map(|y| Self {
            x,
            y,
            infinity: false,
        })
    }

    /// Point of infinity
    pub fn identity() -> Self {
        Self {
            x: MontFelt::ZERO,
            y: MontFelt::ZERO,
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

        // l = (3x^2+a)/2y with a=1 from stark curve
        let lambda = {
            let dividend = MontFelt::THREE * (self.x * self.x) + MontFelt::ONE;
            let divisor_inv = (MontFelt::TWO * self.y).inverse().unwrap();
            dividend * divisor_inv
        };

        let result_x = (lambda * lambda) - self.x - self.x;
        self.y = lambda * (self.x - result_x) - self.y;
        self.x = result_x;
    }

    /// Add a point to this point
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
            let divisor_inv = (other.x - self.x).inverse().unwrap();
            dividend * divisor_inv
        };

        let result_x = (lambda * lambda) - self.x - other.x;
        self.y = lambda * (self.x - result_x) - self.y;
        self.x = result_x;
    }

    /// Multiply a point by a scalar
    pub fn multiply(&self, bits: &BitSlice<u64, Lsb0>) -> AffinePoint {
        let mut product = AffinePoint::identity();
        for b in bits.iter().rev() {
            product.double();
            if *b {
                product.add(self);
            }
        }
        product
    }

    /// Multiply a point by a curve order field element
    pub fn multiply_elm(&self, elm: &MontFelt) -> AffinePoint {
        let bits = elm.into_le_bits();
        self.multiply(bits.as_bitslice())
    }
}
