use serde::{Deserialize, Serialize};

/// The type for the consensus value being agreed upon by consensus.
pub type ValueId = p2p_proto::common::Hash;

/// A convenience wrapper around the consensus value.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ConsensusValue(p2p_proto::common::Hash);

impl ConsensusValue {
    pub fn new(hash: p2p_proto::common::Hash) -> Self {
        Self(hash)
    }

    pub fn into_inner(self) -> p2p_proto::common::Hash {
        self.0
    }

    #[cfg(test)]
    pub fn from_hex_str(s: &str) -> Self {
        Self(p2p_proto::common::Hash(
            pathfinder_crypto::Felt::from_hex_str(s).unwrap(),
        ))
    }
}

impl malachite_types::Value for ConsensusValue {
    type Id = ValueId;

    fn id(&self) -> Self::Id {
        self.0
    }
}

impl std::fmt::Debug for ConsensusValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", short_val(&self.0))
    }
}

impl From<p2p_proto::common::Hash> for ConsensusValue {
    fn from(hash: p2p_proto::common::Hash) -> Self {
        Self(hash)
    }
}

// Shorten the value for debugging purposes.
fn short_val(val: &p2p_proto::common::Hash) -> String {
    let val_str = val.0.to_hex_str();
    if val_str.len() < 8 {
        val_str.to_string()
    } else {
        val_str.chars().skip(val_str.len() - 8).collect()
    }
}
