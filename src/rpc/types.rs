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
/// Which allows for skipping leading zeros in serialized hex strings.
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

/// Groups all strictly output types of the RPC API.
pub mod reply {
    use crate::serde::H256AsRelaxedHexStr;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use web3::types::{H160, H256};

    /// Describes Starknet's syncing status RPC reply.
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
            highest_block: BlockStatus,
        }

        /// Represents highest block status.
        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub enum BlockStatus {
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

    /// L2 Block as returned by the RPC API.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Block {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        block_hash: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        parent_hash: H256,
        block_number: u64,
        status: syncing::BlockStatus,
        sequencer: H160,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        new_root: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        old_root: H256,
        accepted_time: u64,
        #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
        transactions: Vec<H256>,
    }

    /// Starkware specific RPC error codes.
    #[derive(Copy, Clone, Debug, PartialEq)]
    pub enum ErrorCode {
        ContractNotFound = -32020,
        InvaldStorageKey = -32023,
        InvalidBlockNumber = -32025,
    }

    /// L2 state update as returned by the RPC API.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct StateUpdate {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        block_hash: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        new_root: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        old_root: H256,
        accepted_time: u64,
        state_diff: state_update::StateDiff,
    }

    /// State update related substructures.
    pub mod state_update {
        use crate::serde::H256AsRelaxedHexStr;
        use serde::{Deserialize, Serialize};
        use serde_with::serde_as;
        use web3::types::H256;

        /// L2 state diff.
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct StateDiff {
            storage_diffs: Vec<StorageDiff>,
            contracts: Vec<Contract>,
        }

        /// L2 storage diff.
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct StorageDiff {
            #[serde_as(as = "H256AsRelaxedHexStr")]
            address: H256,
            #[serde_as(as = "H256AsRelaxedHexStr")]
            key: H256,
            #[serde_as(as = "H256AsRelaxedHexStr")]
            value: H256,
        }

        /// L2 contract data within state diff.
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Contract {
            #[serde_as(as = "H256AsRelaxedHexStr")]
            address: H256,
            #[serde_as(as = "H256AsRelaxedHexStr")]
            contract_hash: H256,
        }
    }
}
