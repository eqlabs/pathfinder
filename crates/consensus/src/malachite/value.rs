use serde::{Deserialize, Serialize};

/// A value id for the malachite context.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ValueId(p2p_proto::common::Hash);

impl From<p2p_proto::common::Hash> for ValueId {
    fn from(hash: p2p_proto::common::Hash) -> Self {
        Self(hash)
    }
}

impl ValueId {
    pub fn new(hash: p2p_proto::common::Hash) -> Self {
        Self(hash)
    }

    pub fn into_inner(self) -> p2p_proto::common::Hash {
        self.0
    }
}

impl std::fmt::Display for ValueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_val = short_val(&self.0);
        write!(f, "{short_val:?}")
    }
}

impl std::fmt::Debug for ValueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let short_val = short_val(&self.0);
        write!(f, "{short_val:?}")
    }
}

fn short_val(val: &p2p_proto::common::Hash) -> String {
    let val_str = val.0.to_hex_str();
    val_str.chars().skip(val_str.len() - 8).collect()
}

/// The actual value being agreed upon.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ConsensusValue(ValueId);

impl ConsensusValue {
    pub fn new(value_id: ValueId) -> Self {
        Self(value_id)
    }
}

impl From<p2p_proto::common::Hash> for ConsensusValue {
    fn from(hash: p2p_proto::common::Hash) -> Self {
        Self(ValueId::new(hash))
    }
}

impl malachite_types::Value for ConsensusValue {
    type Id = ValueId;

    fn id(&self) -> Self::Id {
        self.0.clone()
    }
}
