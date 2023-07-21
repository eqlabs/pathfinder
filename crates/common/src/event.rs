use std::str::FromStr;

use fake::Dummy;
use num_bigint::BigUint;
use serde_with::serde_conv;
use stark_hash::Felt;

use crate::{ContractAddress, EventData, EventKey};

#[serde_with::serde_as]
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Dummy)]
#[serde(deny_unknown_fields)]
pub struct Event {
    #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
    pub data: Vec<EventData>,
    pub from_address: ContractAddress,
    #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
    pub keys: Vec<EventKey>,
}

serde_conv!(
    EventDataAsDecimalStr,
    EventData,
    |serialize_me: &EventData| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(EventData)
);

serde_conv!(
    EventKeyAsDecimalStr,
    EventKey,
    |serialize_me: &EventKey| starkhash_to_dec_str(&serialize_me.0),
    |s: &str| starkhash_from_dec_str(s).map(EventKey)
);

/// A helper conversion function. Only use with __sequencer API related types__.
fn starkhash_to_dec_str(h: &Felt) -> String {
    let b = h.to_be_bytes();
    let b = BigUint::from_bytes_be(&b);
    b.to_str_radix(10)
}

/// A helper conversion function. Only use with __sequencer API related types__.
fn starkhash_from_dec_str(s: &str) -> Result<Felt, anyhow::Error> {
    match BigUint::from_str(s) {
        Ok(b) => {
            let h = Felt::from_be_slice(&b.to_bytes_be())?;
            Ok(h)
        }
        Err(_) => {
            let h = Felt::from_hex_str(s)?;
            Ok(h)
        }
    }
}
