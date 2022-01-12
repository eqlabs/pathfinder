//! Data structures used by the JSON-RPC API methods.
use crate::serde::H256AsRelaxedHexStr;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use web3::types::H256;

/// Special tag used when specifying the `latest` or `pending` block.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum Tag {
    /// The most recent fully constructed block
    ///
    /// Represented as the JSON string `"latest"` when passed as an RPC method argument,
    /// for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockByHash","params":["latest"]}`
    #[serde(rename = "latest")]
    Latest,
    /// Currently constructed block
    ///
    /// Represented as the JSON string `"pending"` when passed as an RPC method argument,
    /// for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockByHash","params":["pending"]}`
    #[serde(rename = "pending")]
    Pending,
}

/// A wrapper that contains either a [Hash](self::BlockHashOrTag::Hash) or a [Tag](self::BlockHashOrTag::Tag).
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockHashOrTag {
    /// Hash of a block
    ///
    /// Represented as a `0x`-prefixed hex JSON string of length from 1 up to 64 characters
    /// when passed as an RPC method argument, for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockByHash","params":["0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"]}`
    Hash(#[serde_as(as = "H256AsRelaxedHexStr")] H256),
    /// Special [Tag](crate::rpc::types::Tag) describing a block
    Tag(Tag),
}

/// A wrapper that contains either a block [Number](self::BlockNumberOrTag::Number) or a [Tag](self::BlockNumberOrTag::Tag).
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockNumberOrTag {
    /// Number (height) of a block
    Number(u64),
    /// Special [Tag](crate::rpc::types::Tag) describing a block
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

    impl From<crate::sequencer::reply::Call> for Vec<H256> {
        fn from(call: crate::sequencer::reply::Call) -> Self {
            call.result.into_iter().map(H256::from).collect()
        }
    }
}

/// Groups all strictly input types of the RPC API.
pub mod request {
    use crate::serde::H256AsRelaxedHexStr;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use web3::types::H256;

    /// Contains parameters passed to `starknet_call`.
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

    /// Determines the type of response to block related queries.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum BlockResponseScope {
        #[serde(rename = "TXN_HASH")]
        TransactionHashes,
        #[serde(rename = "FULL_TXNS")]
        FullTransactions,
        #[serde(rename = "FULL_TXN_AND_RECEIPTS")]
        FullTransactionsAndReceipts,
    }

    impl Default for BlockResponseScope {
        fn default() -> Self {
            BlockResponseScope::TransactionHashes
        }
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    // At the moment both reply types are the same for get_code, hence the re-export
    use super::request::BlockResponseScope;
    pub use crate::sequencer::reply::Code;
    use crate::{
        sequencer::reply as seq, sequencer::reply::block::Status as SeqStatus,
        serde::H256AsRelaxedHexStr,
    };
    use jsonrpsee::types::{CallError, Error};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::convert::From;
    use web3::types::{H160, H256};

    /// L2 Block status as returned by the RPC API.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum BlockStatus {
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "PROVEN")]
        Proven,
        #[serde(rename = "ACCEPTED_ON_L2")]
        AcceptedOnL2,
        #[serde(rename = "ACCEPTED_ON_L1")]
        AcceptedOnL1,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl From<SeqStatus> for BlockStatus {
        fn from(status: SeqStatus) -> Self {
            match status {
                // TODO verify this mapping with Starkware
                SeqStatus::AcceptedOnL1 => BlockStatus::AcceptedOnL1,
                SeqStatus::AcceptedOnL2 => BlockStatus::AcceptedOnL2,
                SeqStatus::NotReceived => BlockStatus::Rejected,
                SeqStatus::Pending => BlockStatus::Pending,
                SeqStatus::Received => BlockStatus::Pending,
                SeqStatus::Rejected => BlockStatus::Rejected,
                SeqStatus::Reverted => BlockStatus::Rejected,
            }
        }
    }

    /// Wrapper for transaction data returned in block related queries,
    /// chosen variant depends on [BlockResponseScope](crate::rpc::types::request::BlockResponseScope).
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    #[serde(untagged)]
    pub enum Transactions {
        HashesOnly(#[serde_as(as = "Vec<H256AsRelaxedHexStr>")] Vec<H256>),
        Full(Vec<Transaction>),
        FullWithReceipts(Vec<TransactionAndReceipt>),
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
        transactions: Transactions,
    }

    impl Block {
        pub fn from_scoped(block: seq::Block, scope: BlockResponseScope) -> Self {
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
                transactions: match scope {
                    BlockResponseScope::TransactionHashes => Transactions::HashesOnly(
                        block
                            .transactions
                            .into_iter()
                            .map(|t| t.transaction_hash)
                            .collect(),
                    ),
                    BlockResponseScope::FullTransactions => Transactions::Full(
                        block.transactions.into_iter().map(|t| t.into()).collect(),
                    ),
                    BlockResponseScope::FullTransactionsAndReceipts => {
                        Transactions::FullWithReceipts(
                            block
                                .transactions
                                .into_iter()
                                .zip(block.transaction_receipts.into_iter())
                                .map(|(t, r)| TransactionAndReceipt {
                                    transaction: t.into(),
                                    receipt: r.into(),
                                })
                                .collect(),
                        )
                    }
                },
            }
        }
    }

    /// Starkware specific RPC error codes.
    // TODO verify with Starkware how `sequencer::reply::starknet::ErrorCode` should
    // map to the values below in all JSON-RPC API methods. Also verify if
    // the mapping should be method-specific or common for all methods.
    #[derive(Copy, Clone, Debug, PartialEq)]
    pub enum ErrorCode {
        FailedToReceiveTransaction = -32001,
        ContractNotFound = -32020,
        InvalidMessageSelector = -32021,
        InvalidCallData = -32022,
        InvalidStorageKey = -32023,
        InvalidBlockHash = -32024,
        InvalidBlockNumber = -32025,
        ContractError = -32040,
    }

    impl ErrorCode {
        // Workaround for a duplicate error code value
        #[allow(non_upper_case_globals)]
        pub const InvalidTransactionHash: ErrorCode = ErrorCode::InvalidBlockNumber;
        #[allow(non_upper_case_globals)]
        pub const InvalidTransactionHashStr: &'static str = "Invalid transaction hash";
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

    impl From<seq::transaction::Transaction> for Transaction {
        fn from(txn: seq::transaction::Transaction) -> Self {
            Self {
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
            }
        }
    }

    /// L2 transaction receipt as returned by the RPC API.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TransactionReceipt {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        txn_hash: H256,
        status: TransactionStatus,
        #[serde(rename = "statusData")]
        status_data: String,
        messages_sent: Vec<transaction_receipt::MessageToL1>,
        l1_origin_message: transaction_receipt::MessageToL2,
        events: Vec<transaction_receipt::Event>,
    }

    impl From<seq::transaction::Receipt> for TransactionReceipt {
        fn from(receipt: seq::transaction::Receipt) -> Self {
            Self {
                txn_hash: receipt.transaction_hash,
                status: receipt.status.into(),
                // TODO at the moment not available in sequencer replies
                status_data: String::new(),
                messages_sent: receipt
                    .l2_to_l1_messages
                    .iter()
                    .map(transaction_receipt::MessageToL1::from)
                    .collect(),
                l1_origin_message: match receipt.l1_to_l2_consumed_message {
                    Some(m) => m.into(),
                    None => transaction_receipt::MessageToL2::default(),
                },
                // TODO at the moment not available in sequencer replies
                events: vec![],
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

        /// Message sent from L2 to L1.
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

        /// Message sent from L1 to L2.
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

        /// Event emitted as a part of a transaction.
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Event {
            #[serde_as(as = "H256AsRelaxedHexStr")]
            from_address: H256,
            #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
            keys: Vec<H256>,
            #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
            data: Vec<H256>,
        }
    }

    /// Used in [Block](crate::rpc::types::reply::Block) when the requested scope of
    /// reply is [BlockResponseScope::FullTransactionsAndReceipts](crate::rpc::types::request::BlockResponseScope).
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TransactionAndReceipt {
        #[serde(flatten)]
        transaction: Transaction,
        #[serde(flatten)]
        receipt: TransactionReceipt,
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
        #[serde(rename = "ACCEPTED_ON_L2")]
        AcceptedOnL2,
        #[serde(rename = "ACCEPTED_ON_L1")]
        AcceptedOnL1,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl From<seq::transaction::Status> for TransactionStatus {
        fn from(status: SeqStatus) -> Self {
            match status {
                // TODO verify this mapping with Starkware
                SeqStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
                SeqStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
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

    /// Starknet's syncing status substructures.
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
