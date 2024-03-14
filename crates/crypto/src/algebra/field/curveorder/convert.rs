use crate::algebra::curve::CURVE_ORDER;
use crate::{CurveOrderMontFelt, Felt, MontFelt};
use bitvec::prelude::*;

impl CurveOrderMontFelt {
    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let r0 = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let r1 = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let r2 = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let r3 = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);

        let x = CurveOrderMontFelt([r3, r2, r1, r0]);
        x.const_mul(&CurveOrderMontFelt(CurveOrderMontFelt::R2))
    }

    pub const fn to_be_bytes(&self) -> [u8; 32] {
        let s = self.reduce_full();

        let r0 = s.0[0].to_be_bytes();
        let r1 = s.0[1].to_be_bytes();
        let r2 = s.0[2].to_be_bytes();
        let r3 = s.0[3].to_be_bytes();

        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 8 {
            bytes[i] = r3[i];
            bytes[i + 8] = r2[i];
            bytes[i + 16] = r1[i];
            bytes[i + 24] = r0[i];
            i += 1;
        }
        bytes
    }

    /// Create a Montgomery field element from it's native representation
    pub const fn from_raw(x: [u64; 4]) -> Self {
        CurveOrderMontFelt(x)
    }

    /// Get native representation of field element
    pub fn raw(&self) -> [u64; 4] {
        self.0
    }

    /// Create a new field element from a big-integer representation
    pub const fn from_limbs(x: [u64; 4]) -> Self {
        CurveOrderMontFelt::from_raw(x).const_mul(&CurveOrderMontFelt(CurveOrderMontFelt::R2))
    }

    /// Convert a field element to little-endian bits
    pub fn into_le_bits(self) -> BitArray<[u64; 4], Lsb0> {
        let raw = self.reduce_full();
        raw.0.into()
    }
}

impl TryFrom<MontFelt> for CurveOrderMontFelt {
    type Error = ();
    fn try_from(value: MontFelt) -> Result<Self, Self::Error> {
        if value < CURVE_ORDER {
            let bytes = value.to_be_bytes();
            Ok(Self::from_be_bytes(bytes))
        } else {
            Err(())
        }
    }
}

impl TryFrom<Felt> for CurveOrderMontFelt {
    type Error = ();
    /// Converts a felt element to a curve-order field element if less than the curve order
    fn try_from(value: Felt) -> Result<Self, Self::Error> {
        let montvalue = MontFelt::from(value);
        if montvalue < CURVE_ORDER {
            Ok(Self::from_be_bytes(value.to_be_bytes()))
        } else {
            Err(())
        }
    }
}
