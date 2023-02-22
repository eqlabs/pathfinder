use pathfinder_common::{StarknetBlockHash, StarknetBlockNumber};
use pathfinder_serde::StarknetBlockNumberAsHexStr;
use serde::Serialize;
use serde_with::serde_as;

/// Describes Starknet's syncing status RPC reply.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
#[serde(untagged)]
pub enum Syncing {
    False(bool),
    Status(Status),
}

impl std::fmt::Display for Syncing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Syncing::False(_) => f.write_str("false"),
            Syncing::Status(status) => {
                write!(f, "{status}")
            }
        }
    }
}

/// Represents Starknet node syncing status.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
pub struct Status {
    #[serde(flatten, with = "prefix_starting")]
    pub starting: NumberedBlock,
    #[serde(flatten, with = "prefix_current")]
    pub current: NumberedBlock,
    #[serde(flatten, with = "prefix_highest")]
    pub highest: NumberedBlock,
}

serde_with::with_prefix!(prefix_starting "starting_");
serde_with::with_prefix!(prefix_current "current_");
serde_with::with_prefix!(prefix_highest "highest_");

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "starting: {:?}, current: {:?}, highest: {:?}",
            self.starting, self.current, self.highest,
        )
    }
}

/// Block hash and a number, for `starknet_syncing` response only.
#[serde_as]
#[derive(Clone, Copy, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
pub struct NumberedBlock {
    #[serde(rename = "block_hash")]
    pub hash: StarknetBlockHash,
    #[serde_as(as = "StarknetBlockNumberAsHexStr")]
    #[serde(rename = "block_num")]
    pub number: StarknetBlockNumber,
}

impl std::fmt::Debug for NumberedBlock {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "({}, {})", self.hash.0, self.number.get())
    }
}

impl From<(StarknetBlockHash, StarknetBlockNumber)> for NumberedBlock {
    fn from((hash, number): (StarknetBlockHash, StarknetBlockNumber)) -> Self {
        NumberedBlock { hash, number }
    }
}

/// Helper to make it a bit less painful to write examples.
#[cfg(test)]
impl<'a> From<(&'a str, u64)> for NumberedBlock {
    fn from((h, n): (&'a str, u64)) -> Self {
        use stark_hash::Felt;
        NumberedBlock {
            hash: StarknetBlockHash(Felt::from_hex_str(h).unwrap()),
            number: StarknetBlockNumber::new_or_panic(n),
        }
    }
}
