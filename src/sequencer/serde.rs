//! Serialization and deserialiation helpers for L2 sequencer REST API replies.
use bigdecimal::BigDecimal;
use std::fmt::Display;
use web3::{
    ethabi::ethereum_types::FromDecStrErr,
    types::{H160, H256, U256},
};

serde_with::serde_conv!(
    pub U256AsBigDecimal,
    U256,
    |u: &U256| u.to_string(),
    |b: BigDecimal| -> Result<_, FromDecStrErr> { U256::from_dec_str(b.to_string().as_str()) }
);

serde_with::serde_conv!(
    pub U256AsDecimalStr,
    U256,
    |u: &U256| u.to_string(),
    U256::from_dec_str
);

serde_with::serde_conv!(
    pub H256AsRelaxedHexStr,
    H256,
    |h: &H256| *h,
    from_relaxed_hex_str::<H256, {H256::len_bytes()}, {H256::len_bytes() * 2}>
);

serde_with::serde_conv!(
    pub H160AsRelaxedHexStr,
    H160,
    |h: &H160| *h,
    from_relaxed_hex_str::<H160, {H160::len_bytes()}, {H160::len_bytes() * 2}>
);

/// Fixed-size unspecified hash deserialization helper function.
///
/// Python's serde is more liberal, while [`web3::types::U256`] requires exactly
/// a 0x-prefixed 64 character hex string. Works for other fixed-size unspecified hashes too.
/// Unfortuantely redundant `NUM_CHARS` argument is used until
/// `#![feature(generic_const_exprs)]` is stabilized. `NUM_CHARS` should always
/// be equal to `NUM_BYTES * 2`.
pub(super) fn from_relaxed_hex_str<H, const NUM_BYTES: usize, const NUM_CHARS: usize>(
    s: &str,
) -> anyhow::Result<H>
where
    H: From<[u8; NUM_BYTES]> + Display,
{
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let mut bytes = [0u8; NUM_BYTES];

    match stripped.len() {
        0 => return Err(anyhow::anyhow!("At least one hex digit is required.")),
        len if len == NUM_CHARS => hex::decode_to_slice(stripped, &mut bytes)?,
        len if len < NUM_CHARS => {
            let mut extended = [b'0'; NUM_CHARS];
            extended[NUM_BYTES * 2 - stripped.len()..].copy_from_slice(stripped.as_bytes());
            hex::decode_to_slice(extended, &mut bytes)?;
        }
        len => {
            return Err(anyhow::anyhow!(
                "Number of hex digits ({}) is larger than the limit ({}).",
                len,
                NUM_CHARS
            ))
        }
    }

    Ok(H::from(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    mod test_from_relaxed_hex_str {
        use super::*;
        use std::str::FromStr;
        use web3::types::H128;

        #[test]
        fn odd() {
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>("0")
                    .expect("Odd number of hex digits is fine."),
                H128::zero()
            );
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "1234567890123456789012345678901"
                )
                .expect("The max number of hex digits less 1 is also fine."),
                H128::from_str("0x01234567890123456789012345678901").unwrap()
            );
        }

        #[test]
        fn prefixed_odd() {
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "0x0"
                )
                .expect("Odd number of 0x-prefixed hex digits is fine."),
                H128::zero()
            );
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "0x1234567890123456789012345678901"
                )
                .expect("The max number of hex digits less 1 with a 0x-prefix is also fine."),
                H128::from_str("0x01234567890123456789012345678901").unwrap()
            );
        }

        #[test]
        fn even() {
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "00"
                )
                .expect("Even number of hex digits but less than the max is ok."),
                H128::zero()
            );
        }

        #[test]
        fn prefixed_even() {
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "0x00"
                )
                .expect("The same as above but 0x-prefixed is ok too."),
                H128::zero()
            );
        }

        #[test]
        fn exact() {
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "12345678901234567890123456789012"
                )
                .expect("32 hex digits, just as the target type would expect is perfectly ok."),
                H128::from_str("0x12345678901234567890123456789012").unwrap()
            );
        }

        #[test]
        fn prefixed_exact() {
            assert_eq!(
                from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                    "0x12345678901234567890123456789012"
                )
                .expect("The same as above but 0x-prefixed is ok too."),
                H128::from_str("0x12345678901234567890123456789012").unwrap()
            );
        }

        #[test]
        fn empty() {
            from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>("")
                .expect_err("Empty string doesn't make sense.");
        }

        #[test]
        fn prefix_only() {
            from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>("0x")
                .expect_err("The prefix alone is treated like an empty string too.");
        }

        #[test]
        fn invalid_chars() {
            from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                "0x12xy",
            )
            .expect_err("Contains invalid characters.");
        }

        #[test]
        fn too_long() {
            from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                "123456789012345678901234567890123",
            )
            .expect_err("Hex string is too long, this one has 33 digits.");
        }

        #[test]
        fn prefixed_too_long() {
            from_relaxed_hex_str::<H128, { H128::len_bytes() }, { H128::len_bytes() * 2 }>(
                "0x123456789012345678901234567890123",
            )
            .expect_err("The same as above but with a 0x-prefix.");
        }
    }
}
