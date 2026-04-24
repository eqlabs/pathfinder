use fake::Dummy;
use pathfinder_crypto::Felt;
use pathfinder_tagged::Tagged;
use pathfinder_tagged_debug_derive::TaggedDebug;
use serde_with::serde_conv;

use crate::{ContractAddress, EventData, EventKey};

#[serde_with::serde_as]
#[derive(Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq, Dummy, TaggedDebug)]
#[serde(deny_unknown_fields)]
pub struct Event {
    #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
    pub data: Vec<EventData>,
    pub from_address: ContractAddress,
    #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
    pub keys: Vec<EventKey>,
}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct EventIndex(pub u64);

serde_conv!(
    EventDataAsDecimalStr,
    EventData,
    |serialize_me: &EventData| serialize_me.0.to_dec_str(),
    |s: &str| Felt::from_dec_str(s).map(EventData)
);

serde_conv!(
    EventKeyAsDecimalStr,
    EventKey,
    |serialize_me: &EventKey| serialize_me.0.to_dec_str(),
    |s: &str| Felt::from_dec_str(s).map(EventKey)
);
