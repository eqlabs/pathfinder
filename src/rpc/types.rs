use crate::serde::H256AsRelaxedHexStr;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use web3::types::H256;

/// Special tag used when specifying the latest block.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum Tag {
    #[serde(rename = "latest")]
    Latest,
}

/// A wrapper that contains either a block hash or the special `latest` tag.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockHashOrTag {
    Hash(#[serde_as(as = "H256AsRelaxedHexStr")] H256),
    Tag(Tag),
}

/// A wrapper that contains either a block number or the special `latest` tag.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockNumberOrTag {
    Number(u64),
    Tag(Tag),
}

/// Contains hash type wrappers enabling deserialization via `*AsRelaxedHexStr`.
pub mod relaxed {
    use crate::serde::H256AsRelaxedHexStr;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::convert::From;
    use web3::types;

    #[serde_as]
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct H256(#[serde_as(as = "H256AsRelaxedHexStr")] types::H256);

    impl From<types::H256> for H256 {
        fn from(core: types::H256) -> Self {
            H256(core)
        }
    }

    use std::ops::Deref;

    impl Deref for H256 {
        type Target = types::H256;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
}

/// Describes Starknet's syncing status RPC reply.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum Syncing {
    False(bool),
    Status(syncing::Status),
}

pub mod syncing {
    use crate::serde::H256AsRelaxedHexStr;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use web3::types::H256;

    /// Represents Starknet node syncing status.
    #[serde_as]
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Status {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        starting_block: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        current_block: H256,
        highest_block: HighestBlock,
    }

    /// Represents highest block status.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum HighestBlock {
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "PROVEN")]
        Proven,
        #[serde(rename = "ACCEPTED_ONCHAIN")]
        AcceptedOnChain,
        #[serde(rename = "REJECTED")]
        Rejected,
    }
}
