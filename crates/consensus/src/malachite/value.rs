use serde::{Deserialize, Serialize};

impl ConsensusBounded for p2p_proto::common::Hash {}

/// A bounded trait for the consensus value.
pub trait ConsensusBounded:
    Serialize
    + for<'de> Deserialize<'de>
    + Clone
    + Eq
    + Ord
    + std::fmt::Debug
    + std::fmt::Display
    + Send
    + Sync
{
}

/// A convenience wrapper around the consensus value.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[repr(transparent)]
pub struct ConsensusValue<V> {
    pub value: V,
}

impl<V: ConsensusBounded> ConsensusValue<V> {
    pub fn new(value: V) -> Self {
        Self { value }
    }

    pub fn into_inner(self) -> V {
        self.value
    }
}

impl<V: ConsensusBounded> malachite_types::Value for ConsensusValue<V> {
    type Id = V;

    fn id(&self) -> Self::Id {
        self.value.clone()
    }
}

impl<V: ConsensusBounded> From<V> for ConsensusValue<V> {
    fn from(value: V) -> Self {
        Self { value }
    }
}

// Shorten the value for debugging purposes. /// **********
fn short_val(val: &p2p_proto::common::Hash) -> String {
    let val_str = val.0.to_hex_str();
    if val_str.len() < 8 {
        val_str.to_string()
    } else {
        val_str.chars().skip(val_str.len() - 8).collect()
    }
}
