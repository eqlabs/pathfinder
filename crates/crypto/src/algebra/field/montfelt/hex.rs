use crate::MontFelt;

impl MontFelt {
    pub fn to_hex(&self) -> String {
        const ALPHABET: &[u8] = "0123456789ABCDEF".as_bytes();
        let mut buf: Vec<u8> = vec![0u8; 64];
        let mut i = 0;
        while i < 4 {
            let limb = self.0[3 - i];
            let mut j = 0;
            while j < 16 {
                let v = (limb >> ((15 - j) * 4)) & 0xFu64;
                buf[i * 16 + j] = ALPHABET[v as usize];
                j += 1;
            }
            i += 1;
        }
        // SAFETY: Only hex characters are used, making this safe.
        unsafe { String::from_utf8_unchecked(buf) }
    }

    pub const fn from_hex(s: &str) -> MontFelt {
        let s_bytes = s.as_bytes();

        let mut res = [0u64; 4];
        let mut i = 0;
        let mut j = 0;
        let mut tmp = 0;

        let mut idx = s_bytes.len();
        while idx > 0 {
            idx -= 1;
            let c = s_bytes[idx];
            let v = match c {
                b'0'..=b'9' => c as u64 - b'0' as u64,
                b'a'..=b'f' => c as u64 - b'a' as u64 + 10,
                b'A'..=b'F' => c as u64 - b'A' as u64 + 10,
                _ => panic!("invalid hex"),
            };
            tmp |= v << (i * 4);
            i += 1;
            if i == 16 {
                res[j] = tmp;
                tmp = 0;
                i = 0;
                j += 1;
            }
        }
        if i != 0 {
            res[j] = tmp;
        }

        let x = MontFelt([res[0], res[1], res[2], res[3]]);
        x.const_mul(&MontFelt(MontFelt::R2))
    }
}
