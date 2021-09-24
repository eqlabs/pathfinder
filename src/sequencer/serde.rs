//! Serialization and deserialiation helpers for L2 sequencer REST API replies.
use bigdecimal::BigDecimal;
use serde::ser::StdError;
use std::{fmt::Display, str::FromStr};
use web3::{
    ethabi::ethereum_types::FromDecStrErr,
    types::{H160, H256, U256},
};

serde_with::serde_conv!(
    pub U256AsBigDecimal,
    U256,
    |u: &U256| *u,
    |b: BigDecimal| -> Result<_, FromDecStrErr> { U256::from_dec_str(b.to_string().as_str()) }
);

serde_with::serde_conv!(
    pub U256AsDecimalStr,
    U256,
    |u: &U256| *u,
    U256::from_dec_str
);

serde_with::serde_conv!(
    pub H256AsRelaxedHexStr,
    H256,
    |h: &H256| *h,
    from_relaxed_hex_str::<H256, {H256::len_bytes()}>
);

serde_with::serde_conv!(
    pub H160AsRelaxedHexStr,
    H160,
    |h: &H160| *h,
    from_relaxed_hex_str::<H160, {H160::len_bytes()}>
);

/// Fixed-size unspecified hash deserialization helper function.
///
/// Python's serde is more liberal, while [`web3::types::U256`] requires exactly
/// a 0x-prefixed 64 character hex string. Works for other fixed-size unspecified hashes too.
pub(super) fn from_relaxed_hex_str<H, const NUM_BYTES: usize>(s: &str) -> anyhow::Result<H>
where
    H: FromStr + Display,
    H::Err: 'static + Display + Send + Sync + StdError,
{
    let has_0x = s.starts_with("0x");
    let req_len = if has_0x {
        2 + NUM_BYTES * 2
    } else {
        NUM_BYTES * 2
    };

    use std::cmp::Ordering;

    match s.len().cmp(&req_len) {
        Ordering::Equal => {
            if has_0x {
                let h = H::from_str(s)?;
                Ok(h)
            } else {
                let x_clone = format!("0x{}", s);
                let h = H::from_str(x_clone.as_str())?;
                Ok(h)
            }
        }
        Ordering::Greater => Err(anyhow::anyhow!(
            "value: invalid lenght {}, expected a 0x-prefixed hex string with length of 64 or smaller",
            if has_0x { s.len() - 2 } else { s.len() }
        )),
        Ordering::Less => {
            let start = if has_0x {2} else {0};
            // Pad with missing leading 0s
            let h = H::from_str(format!("0x{:0>64}", &s[start..]).as_str())?;
            Ok(h)
        }
    }
}
