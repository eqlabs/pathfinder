//! Data structures used by the JSON-RPC API methods.
use crate::core::{StarknetBlockHash, StarknetBlockNumber};
use serde::{Deserialize, Serialize};

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
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockHashOrTag {
    /// Hash of a block
    ///
    /// Represented as a `0x`-prefixed hex JSON string of length from 1 up to 64 characters
    /// when passed as an RPC method argument, for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockByHash","params":["0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"]}`
    Hash(StarknetBlockHash),
    /// Special [Tag](crate::rpc::types::Tag) describing a block
    Tag(Tag),
}

/// A wrapper that contains either a block [Number](self::BlockNumberOrTag::Number) or a [Tag](self::BlockNumberOrTag::Tag).
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockNumberOrTag {
    /// Number (height) of a block
    Number(StarknetBlockNumber),
    /// Special [Tag](crate::rpc::types::Tag) describing a block
    Tag(Tag),
}

/// Groups all strictly input types of the RPC API.
pub mod request {
    use crate::{
        core::{CallParam, ContractAddress, EntryPoint, EventKey, StarknetBlockNumber},
        rpc::serde::H256AsNoLeadingZerosHexStr,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use web3::types::H256;

    /// The address of a storage element for a StarkNet contract.
    ///
    /// __This type is not checked for 251 bits overflow__ in contrast to
    /// [`StarkHash`](pedersen::StarkHash).
    #[serde_as]
    #[derive(Debug, Copy, Clone, PartialEq, Deserialize, Serialize)]
    pub struct OverflowingStorageAddress(#[serde_as(as = "H256AsNoLeadingZerosHexStr")] pub H256);

    /// Contains parameters passed to `starknet_call`.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Call {
        pub contract_address: ContractAddress,
        pub calldata: Vec<CallParam>,
        pub entry_point_selector: EntryPoint,
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

    /// Contains event filter parameters passed to `starknet_getEvents`.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct EventFilter {
        #[serde(default, rename = "fromBlock")]
        pub from_block: Option<StarknetBlockNumber>,
        #[serde(default, rename = "toBlock")]
        pub to_block: Option<StarknetBlockNumber>,
        #[serde(default)]
        pub address: Option<ContractAddress>,
        #[serde(default)]
        pub keys: Vec<EventKey>,

        // These are inlined here because serde flatten and deny_unknown_fields
        // don't work together.
        pub page_size: Option<usize>,
        pub page_number: Option<usize>,
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    // At the moment both reply types are the same for get_code, hence the re-export
    use super::request::BlockResponseScope;
    use crate::{
        core::{
            CallParam, ContractAddress, EntryPoint, EventData, EventKey, GlobalRoot,
            StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
            StarknetTransactionHash,
        },
        rpc::api::RawBlock,
        sequencer::reply as seq,
        sequencer::reply::Status as SeqStatus,
    };
    use jsonrpsee::types::{CallError, Error};
    use pedersen::StarkHash;
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::convert::From;
    use web3::types::H160;

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
                SeqStatus::Aborted => BlockStatus::Rejected,
            }
        }
    }

    /// Wrapper for transaction data returned in block related queries,
    /// chosen variant depends on [BlockResponseScope](crate::rpc::types::request::BlockResponseScope).
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    #[serde(untagged)]
    pub enum Transactions {
        HashesOnly(Vec<StarknetTransactionHash>),
        // __Extremely important!!!__
        // This variant needs to come __before__ `Full`
        // as it contains a structure which has the same fields
        // as `Full` plus some additional fields.
        // Which means that `serde` would always wrongly deserialize
        // to the smaller variant if the order here was swapped
        // (ie. smaller variant first, bigger next).
        FullWithReceipts(Vec<TransactionAndReceipt>),
        Full(Vec<Transaction>),
    }

    /// L2 Block as returned by the RPC API.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Block {
        pub block_hash: Option<StarknetBlockHash>,
        pub parent_hash: StarknetBlockHash,
        pub block_number: Option<StarknetBlockNumber>,
        pub status: BlockStatus,
        pub sequencer: H160,
        pub new_root: Option<GlobalRoot>,
        pub old_root: GlobalRoot,
        pub accepted_time: StarknetBlockTimestamp,
        pub transactions: Transactions,
    }

    impl Block {
        pub fn from_raw(block: RawBlock, transactions: Transactions) -> Self {
            Self {
                block_hash: Some(block.hash),
                parent_hash: block.parent_hash,
                block_number: Some(block.number),
                status: block.status,
                // This only matters once the sequencers are distributed.
                sequencer: H160::zero(),
                new_root: Some(block.root),
                old_root: block.parent_root,
                accepted_time: block.timestamp,
                transactions,
            }
        }

        pub fn from_sequencer_scoped(block: seq::Block, scope: BlockResponseScope) -> Self {
            Self {
                block_hash: block.block_hash,
                parent_hash: block.parent_block_hash,
                block_number: block.block_number,
                status: block.status.into(),
                // This only matters once the sequencers are distributed.
                sequencer: H160::zero(),
                new_root: block.state_root,
                // TODO where to get it from
                old_root: GlobalRoot(StarkHash::ZERO),
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
                                .map(|(t, r)| {
                                    let t: Transaction = t.into();
                                    let r = TransactionReceipt::with_status(r, block.status.into());

                                    TransactionAndReceipt {
                                        txn_hash: t.txn_hash,
                                        contract_address: t.contract_address,
                                        entry_point_selector: t.entry_point_selector,
                                        calldata: t.calldata,
                                        status: r.status,
                                        status_data: r.status_data,
                                        messages_sent: r.messages_sent,
                                        l1_origin_message: r.l1_origin_message,
                                        events: r.events,
                                    }
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
        FailedToReceiveTransaction = 1,
        ContractNotFound = 20,
        InvalidMessageSelector = 21,
        InvalidCallData = 22,
        InvalidStorageKey = 23,
        InvalidBlockHash = 24,
        InvalidTransactionHash = 25,
        InvalidBlockNumber = 26,
        InvalidTransactionIndex = 27,
        ContractError = 40,
    }

    /// We can have this equality and should have it in order to use it for tests. It is meant to
    /// be used when expecting that the rpc result is an error. The rpc result should first be
    /// accessed with [`Result::unwrap_err`], then compared to the expected [`ErrorCode`] with
    /// [`assert_eq!`].
    #[cfg(test)]
    impl PartialEq<jsonrpsee::types::Error> for ErrorCode {
        fn eq(&self, other: &jsonrpsee::types::Error) -> bool {
            use jsonrpsee::types::Error::*;

            // the interesting variant Error::Request holds the whole error value as a raw string,
            // which looks like FailedResponse.
            //
            // RpcError could have more user error body, which is why there's the
            // deny_unknown_fields, as when writing this there were no such extra types being used.

            #[derive(serde::Deserialize, Debug)]
            pub struct FailedResponse<'a> {
                // we don't really care about this when testing; version
                #[serde(borrow, rename = "jsonrpc")]
                _jsonrpc: &'a serde_json::value::RawValue,
                // don't care: request id
                #[serde(borrow, rename = "id")]
                _id: &'a serde_json::value::RawValue,
                #[serde(borrow)]
                error: RpcError<'a>,
            }

            #[derive(serde::Deserialize, Debug)]
            #[serde(deny_unknown_fields)]
            pub struct RpcError<'a> {
                code: i32,
                #[serde(borrow)]
                message: std::borrow::Cow<'a, str>,
            }

            impl PartialEq<ErrorCode> for FailedResponse<'_> {
                fn eq(&self, rhs: &ErrorCode) -> bool {
                    if let Ok(lhs) = ErrorCode::try_from(self.error.code) {
                        // make sure the error matches what we think it was; it's ... a bit extra,
                        // but shouldn't really be an issue.
                        &*self.error.message == lhs.as_str() && &lhs == rhs
                    } else {
                        false
                    }
                }
            }

            let resp = match other {
                Request(ref s) => serde_json::from_str::<FailedResponse>(s),
                _ => return false,
            };

            if let Ok(resp) = resp {
                &resp == self
            } else {
                // Parsing failure doesn't really matter, and we don't need to panic; the assert_eq
                // will make sure we'll have informative panic.
                false
            }
        }
    }

    impl TryFrom<i32> for ErrorCode {
        type Error = i32;

        fn try_from(code: i32) -> Result<ErrorCode, Self::Error> {
            use ErrorCode::*;
            Ok(match code {
                1 => FailedToReceiveTransaction,
                20 => ContractNotFound,
                21 => InvalidMessageSelector,
                22 => InvalidCallData,
                23 => InvalidStorageKey,
                24 => InvalidBlockHash,
                25 => InvalidTransactionHash,
                26 => InvalidBlockNumber,
                27 => InvalidTransactionIndex,
                40 => ContractError,
                x => return Err(x),
            })
        }
    }

    impl ErrorCode {
        fn as_str(&self) -> &'static str {
            match self {
                ErrorCode::FailedToReceiveTransaction => "Failed to write transaction",
                ErrorCode::ContractNotFound => "Contract not found",
                ErrorCode::InvalidMessageSelector => "Invalid message selector",
                ErrorCode::InvalidCallData => "Invalid call data",
                ErrorCode::InvalidStorageKey => "Invalid storage key",
                ErrorCode::InvalidBlockHash => "Invalid block hash",
                ErrorCode::InvalidTransactionHash => "Invalid transaction hash",
                ErrorCode::InvalidBlockNumber => "Invalid block number",
                ErrorCode::InvalidTransactionIndex => "Invalid transaction index in a block",
                ErrorCode::ContractError => "Contract error",
            }
        }
    }

    impl std::string::ToString for ErrorCode {
        fn to_string(&self) -> String {
            self.as_str().to_owned()
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct StateUpdate {
        block_hash: StarknetBlockHash,
        new_root: GlobalRoot,
        old_root: GlobalRoot,
        accepted_time: u64,
        state_diff: state_update::StateDiff,
    }

    /// State update related substructures.
    pub mod state_update {
        use crate::core::{ContractAddress, ContractHash, StorageAddress, StorageValue};
        use serde::{Deserialize, Serialize};

        /// L2 state diff.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct StateDiff {
            storage_diffs: Vec<StorageDiff>,
            contracts: Vec<Contract>,
        }

        /// L2 storage diff.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct StorageDiff {
            address: ContractAddress,
            key: StorageAddress,
            value: StorageValue,
        }

        /// L2 contract data within state diff.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Contract {
            address: ContractAddress,
            contract_hash: ContractHash,
        }
    }

    /// L2 transaction as returned by the RPC API.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct Transaction {
        pub txn_hash: StarknetTransactionHash,
        pub contract_address: ContractAddress,
        /// Absent for "deploy" transactions
        pub entry_point_selector: Option<EntryPoint>,
        /// Absent for "deploy" transactions
        pub calldata: Option<Vec<CallParam>>,
    }

    impl TryFrom<seq::Transaction> for Transaction {
        type Error = anyhow::Error;

        fn try_from(txn: seq::Transaction) -> Result<Self, Self::Error> {
            let txn = txn
                .transaction
                .ok_or_else(|| anyhow::anyhow!("Transaction not found."))?;
            Ok(Self {
                txn_hash: txn.transaction_hash,
                contract_address: txn.contract_address,
                entry_point_selector: txn.entry_point_selector,
                calldata: txn.calldata,
            })
        }
    }

    impl From<seq::transaction::Transaction> for Transaction {
        fn from(txn: seq::transaction::Transaction) -> Self {
            Self {
                txn_hash: txn.transaction_hash,
                contract_address: txn.contract_address,
                entry_point_selector: txn.entry_point_selector,
                calldata: txn.calldata,
            }
        }
    }

    /// L2 transaction receipt as returned by the RPC API.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TransactionReceipt {
        pub txn_hash: StarknetTransactionHash,
        pub status: TransactionStatus,
        pub status_data: String,
        pub messages_sent: Vec<transaction_receipt::MessageToL1>,
        pub l1_origin_message: Option<transaction_receipt::MessageToL2>,
        pub events: Vec<transaction_receipt::Event>,
    }

    impl TransactionReceipt {
        pub fn with_status(receipt: seq::transaction::Receipt, status: BlockStatus) -> Self {
            Self {
                txn_hash: receipt.transaction_hash,
                status: status.into(),
                // TODO at the moment not available in sequencer replies
                status_data: String::new(),
                messages_sent: receipt
                    .l2_to_l1_messages
                    .into_iter()
                    .map(transaction_receipt::MessageToL1::from)
                    .collect(),
                l1_origin_message: receipt
                    .l1_to_l2_consumed_message
                    .map(transaction_receipt::MessageToL2::from),
                // TODO at the moment not available in sequencer replies
                events: vec![],
            }
        }
    }

    /// Transaction receipt related substructures.
    pub mod transaction_receipt {
        use crate::{
            core::{
                ContractAddress, EthereumAddress, EventData, EventKey, L1ToL2MessagePayloadElem,
                L2ToL1MessagePayloadElem,
            },
            rpc::serde::EthereumAddressAsHexStr,
            sequencer::reply::transaction::{L1ToL2Message, L2ToL1Message},
        };
        use serde::{Deserialize, Serialize};
        use serde_with::serde_as;
        use std::convert::From;

        /// Message sent from L2 to L1.
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct MessageToL1 {
            #[serde_as(as = "EthereumAddressAsHexStr")]
            to_address: EthereumAddress,
            payload: Vec<L2ToL1MessagePayloadElem>,
        }

        impl From<L2ToL1Message> for MessageToL1 {
            fn from(msg: L2ToL1Message) -> Self {
                Self {
                    to_address: msg.to_address,
                    payload: msg.payload,
                }
            }
        }

        /// Message sent from L1 to L2.
        #[serde_as]
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct MessageToL2 {
            #[serde_as(as = "EthereumAddressAsHexStr")]
            from_address: EthereumAddress,
            payload: Vec<L1ToL2MessagePayloadElem>,
        }

        impl From<L1ToL2Message> for MessageToL2 {
            fn from(msg: L1ToL2Message) -> Self {
                Self {
                    from_address: msg.from_address,
                    payload: msg.payload,
                }
            }
        }

        /// Event emitted as a part of a transaction.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Event {
            from_address: ContractAddress,
            keys: Vec<EventKey>,
            data: Vec<EventData>,
        }
    }

    /// Used in [Block](crate::rpc::types::reply::Block) when the requested scope of
    /// reply is [BlockResponseScope::FullTransactionsAndReceipts](crate::rpc::types::request::BlockResponseScope).
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct TransactionAndReceipt {
        pub txn_hash: StarknetTransactionHash,
        pub contract_address: ContractAddress,
        /// Absent in "deploy" transaction
        pub entry_point_selector: Option<EntryPoint>,
        /// Absent in "deploy" transaction
        pub calldata: Option<Vec<CallParam>>,
        pub status: TransactionStatus,
        pub status_data: String,
        pub messages_sent: Vec<transaction_receipt::MessageToL1>,
        pub l1_origin_message: Option<transaction_receipt::MessageToL2>,
        pub events: Vec<transaction_receipt::Event>,
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

    impl From<seq::Status> for TransactionStatus {
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
                SeqStatus::Aborted => TransactionStatus::Unknown,
            }
        }
    }

    impl From<BlockStatus> for TransactionStatus {
        fn from(status: BlockStatus) -> Self {
            match status {
                BlockStatus::Pending => TransactionStatus::Pending,
                BlockStatus::Proven => TransactionStatus::Received,
                BlockStatus::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
                BlockStatus::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
                BlockStatus::Rejected => TransactionStatus::Rejected,
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
        use crate::core::StarknetBlockHash;
        use serde::{Deserialize, Serialize};

        /// Represents Starknet node syncing status.
        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Status {
            pub starting_block: StarknetBlockHash,
            pub current_block: StarknetBlockHash,
            pub highest_block: StarknetBlockHash,
        }
    }

    /// Describes an emitted event returned by starknet_getEvents
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct EmittedEvent {
        pub data: Vec<EventData>,
        pub keys: Vec<EventKey>,
        pub from_address: ContractAddress,
        pub block_hash: StarknetBlockHash,
        pub block_number: StarknetBlockNumber,
        pub transaction_hash: StarknetTransactionHash,
    }

    impl From<crate::storage::StarknetEmittedEvent> for EmittedEvent {
        fn from(event: crate::storage::StarknetEmittedEvent) -> Self {
            Self {
                data: event.data,
                keys: event.keys,
                from_address: event.from_address,
                block_hash: event.block_hash,
                block_number: event.block_number,
                transaction_hash: event.transaction_hash,
            }
        }
    }

    // Result type for starknet_getEvents
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct GetEventsResult {
        pub events: Vec<EmittedEvent>,
        pub page_number: usize,
    }
}
