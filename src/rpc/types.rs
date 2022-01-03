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

/// Groups all strictly input types of the RPC API.
pub mod request {
    use crate::serde::H256AsRelaxedHexStr;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use web3::types::H256;

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct Call {
        #[serde(rename = "contractAddress")]
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub contract_address: H256,
        #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
        pub calldata: Vec<H256>,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub entry_point_selector: H256,
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    use crate::{
        sequencer::reply as seq, sequencer::reply::block::Status as SeqStatus,
        serde::H256AsRelaxedHexStr,
    };
    use jsonrpsee::types::{CallError, Error};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::convert::From;
    use web3::types::{H160, H256, U256};

    /// L2 Block status as returned by the RPC API.
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

    impl From<SeqStatus> for BlockStatus {
        fn from(status: SeqStatus) -> Self {
            match status {
                // TODO klis: this is a wild guess right now
                SeqStatus::AcceptedOnL1 => BlockStatus::AcceptedOnChain,
                SeqStatus::AcceptedOnL2 => BlockStatus::Proven,
                SeqStatus::NotReceived => BlockStatus::Rejected,
                SeqStatus::Pending => BlockStatus::Pending,
                SeqStatus::Received => BlockStatus::Pending,
                SeqStatus::Rejected => BlockStatus::Rejected,
                SeqStatus::Reverted => BlockStatus::Rejected,
            }
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
        status: BlockStatus,
        sequencer: H160,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        new_root: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        old_root: H256,
        accepted_time: u64,
        #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
        transactions: Vec<H256>,
    }

    impl From<seq::Block> for Block {
        fn from(block: seq::Block) -> Self {
            Self {
                block_hash: block.block_hash.unwrap_or_default(),
                parent_hash: block.parent_block_hash,
                block_number: block.block_number,
                status: block.status.into(),
                // TODO should be sequencer identity
                sequencer: H160::zero(),
                // TODO check if state_root is the new root
                new_root: block.state_root,
                // TODO where to get it from
                old_root: H256::zero(),
                accepted_time: block.timestamp,
                transactions: block
                    .transactions
                    .iter()
                    .map(|t| t.transaction_hash)
                    .collect(),
            }
        }
    }

    /// Starkware specific RPC error codes.
    #[derive(Copy, Clone, Debug, PartialEq)]
    pub enum ErrorCode {
        // "Failed to write transaction"
        FailedToReceiveTransaction = -32001,
        // "Contract not found"
        ContractNotFound = -32020,
        // "Invalid message selector"
        InvalidMessageSelector = -32021,
        // "Invalid call data"
        InvalidCallData = -32022,
        // "Invalid storage key"
        InvalidStorageKey = -32023,
        // "Invalid block hash"
        InvalidBlockHash = -32024,
        // "Invalid block number"
        InvalidBlockNumber = -32025,
        // "Contract error"
        ContractError = -32040,
    }

    impl ErrorCode {
        // "Invalid transaction hash"
        // TODO jsonrpsee::types::CallError
        #[allow(non_upper_case_globals)]
        pub const InvalidTransactionHash: ErrorCode = ErrorCode::InvalidBlockNumber;
    }

    impl std::string::ToString for ErrorCode {
        fn to_string(&self) -> String {
            match self {
                ErrorCode::FailedToReceiveTransaction => "Failed to write transaction",
                ErrorCode::ContractNotFound => "Contract not found",
                ErrorCode::InvalidMessageSelector => "Invalid message selector",
                ErrorCode::InvalidCallData => "Invalid call data",
                ErrorCode::InvalidStorageKey => "Invalid storage key",
                ErrorCode::InvalidBlockHash => "Invalid block hash",
                ErrorCode::InvalidBlockNumber => "Invalid block number",
                ErrorCode::ContractError => "Contract error",
            }
            .to_owned()
        }
    }

    impl From<ErrorCode> for Error {
        fn from(ecode: ErrorCode) -> Self {
            Error::Call(CallError::Custom {
                code: ecode as i32,
                message: ecode.to_string(),
                data: None,
            })
        }
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

    /// L2 transaction as returned by the RPC API.
    #[serde_as]
    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Transaction {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        txn_hash: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        #[serde(rename = "contractAddress")]
        contract_address: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        entry_point_selector: H256,
        #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
        calldata: Vec<H256>,
    }

    impl From<seq::Transaction> for Transaction {
        fn from(txn: seq::Transaction) -> Self {
            match txn.transaction {
                Some(txn) => Self {
                    txn_hash: txn.transaction_hash,
                    contract_address: txn.contract_address,
                    entry_point_selector: txn.entry_point_selector.unwrap_or_default(),
                    calldata: match txn.calldata {
                        Some(cd) => cd
                            .iter()
                            .map(|d| {
                                let x: [u8; 32] = (*d).into();
                                x.into()
                            })
                            .collect(),
                        None => vec![],
                    },
                },
                None => Self::default(),
            }
        }
    }

    /// L2 transaction receipt as returned by the RPC API.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct TransactionReceipt {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        txn_hash: H256,
        status: TransactionStatus,
        status_data: String,
        messages_sent: Vec<transaction_receipt::MessageToL1>,
        l1_origin_message: transaction_receipt::MessageToL2,
    }

    impl From<seq::transaction::Receipt> for TransactionReceipt {
        fn from(receipt: seq::transaction::Receipt) -> Self {
            Self {
                txn_hash: receipt.transaction_hash,
                status: receipt.status.into(),
                // TODO
                status_data: String::new(),
                messages_sent: receipt
                    .l2_to_l1_messages
                    .iter()
                    .map(|m| transaction_receipt::MessageToL1::from(m))
                    .collect(),
                l1_origin_message: match receipt.l1_to_l2_consumed_message {
                    Some(m) => m.into(),
                    None => transaction_receipt::MessageToL2::default(),
                },
            }
        }
    }

    /// Transaction receipt related substructures.
    pub mod transaction_receipt {
        use crate::{
            sequencer::reply::transaction::{L1ToL2Message, L2ToL1Message},
            serde::{H160AsRelaxedHexStr, H256AsRelaxedHexStr},
        };
        use serde::{Deserialize, Serialize};
        use serde_with::serde_as;
        use std::convert::From;
        use web3::types::{H160, H256};

        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct MessageToL1 {
            #[serde_as(as = "H256AsRelaxedHexStr")]
            to_address: H256,
            #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
            payload: Vec<H256>,
        }

        impl From<&L2ToL1Message> for MessageToL1 {
            fn from(msg: &L2ToL1Message) -> Self {
                Self {
                    to_address: msg.to_address.into(),
                    payload: msg
                        .payload
                        .iter()
                        .map(|p| {
                            let x: [u8; 32] = (*p).into();
                            x.into()
                        })
                        .collect(),
                }
            }
        }

        #[serde_as]
        #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct MessageToL2 {
            #[serde_as(as = "H160AsRelaxedHexStr")]
            from_address: H160,
            #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
            payload: Vec<H256>,
        }

        impl From<L1ToL2Message> for MessageToL2 {
            fn from(msg: L1ToL2Message) -> Self {
                Self {
                    from_address: msg.from_address,
                    payload: msg
                        .payload
                        .iter()
                        .map(|p| {
                            let x: [u8; 32] = (*p).into();
                            x.into()
                        })
                        .collect(),
                }
            }
        }
    }

    /// Represents transaction status.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum TransactionStatus {
        #[serde(rename = "UNKNOWN")]
        Unknown,
        #[serde(rename = "RECEIVED")]
        Received,
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "ACCEPTED_ONCHAIN")]
        AcceptedOnChain,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl From<seq::transaction::Status> for TransactionStatus {
        fn from(status: SeqStatus) -> Self {
            match status {
                // TODO klis: this is a wild guess right now
                SeqStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnChain,
                SeqStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnChain,
                SeqStatus::NotReceived => TransactionStatus::Unknown,
                SeqStatus::Pending => TransactionStatus::Pending,
                SeqStatus::Received => TransactionStatus::Received,
                SeqStatus::Rejected => TransactionStatus::Rejected,
                SeqStatus::Reverted => TransactionStatus::Unknown,
            }
        }
    }

    /// Describes Starknet's syncing status RPC reply.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
    #[serde(untagged)]
    #[serde(deny_unknown_fields)]
    pub enum Syncing {
        False(bool),
        Status(syncing::Status),
    }

    pub mod syncing {
        use super::BlockStatus;
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
    }
}
