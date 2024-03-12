use crate::{Felt, MontFelt};
use bitvec::prelude::*;

impl MontFelt {
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

        let x = MontFelt([r3, r2, r1, r0]);
        x.const_mul(&MontFelt(MontFelt::R2))
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

    /// TODO: remove and use new()
    pub const fn from_raw(x: [u64; 4]) -> Self {
        MontFelt(x)
    }

    /// Create a new field element from a big-integer representation
    pub const fn from_limbs(x: [u64; 4]) -> Self {
        MontFelt::new(x).const_mul(&MontFelt(MontFelt::R2))
    }

    /// Convert a field element to little-endian bits
    pub fn into_le_bits(self) -> BitArray<[u64; 4], Lsb0> {
        let raw = self.reduce_full();
        raw.0.into()
    }
}

impl From<Felt> for MontFelt {
    fn from(felt: Felt) -> Self {
        // safe since the value is below field order
        MontFelt::from_be_bytes(felt.to_be_bytes())
    }
}
