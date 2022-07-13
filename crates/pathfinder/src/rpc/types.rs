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

impl std::fmt::Display for Tag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Tag::Latest => f.write_str("latest"),
            Tag::Pending => f.write_str("pending"),
        }
    }
}

/// A wrapper that contains either a [Hash](self::BlockHashOrTag::Hash) or a [Tag](self::BlockHashOrTag::Tag).
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
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

impl std::fmt::Display for BlockHashOrTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockHashOrTag::Hash(StarknetBlockHash(h)) => f.write_str(&h.to_hex_str()),
            BlockHashOrTag::Tag(t) => std::fmt::Display::fmt(t, f),
        }
    }
}

/// A wrapper that contains either a block [Number](self::BlockNumberOrTag::Number) or a [Tag](self::BlockNumberOrTag::Tag).
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockNumberOrTag {
    /// Number (height) of a block
    Number(StarknetBlockNumber),
    /// Special [Tag](crate::rpc::types::Tag) describing a block
    Tag(Tag),
}

impl std::fmt::Display for BlockNumberOrTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockNumberOrTag::Number(StarknetBlockNumber(n)) => std::fmt::Display::fmt(n, f),
            BlockNumberOrTag::Tag(t) => std::fmt::Display::fmt(t, f),
        }
    }
}

/// Groups all strictly input types of the RPC API.
pub mod request {
    use crate::{
        core::{
            CallParam, CallSignatureElem, ContractAddress, EntryPoint, EventKey, Fee,
            StarknetBlockNumber, TransactionVersion,
        },
        rpc::serde::{
            CallSignatureElemAsDecimalStr, FeeAsHexStr, H256AsNoLeadingZerosHexStr,
            TransactionVersionAsHexStr,
        },
    };
    use serde::Deserialize;
    use serde_with::{serde_as, skip_serializing_none};
    use web3::types::H256;

    /// The address of a storage element for a StarkNet contract.
    ///
    /// __This type is not checked for 251 bits overflow__ in contrast to
    /// [`StarkHash`](stark_hash::StarkHash).
    #[serde_as]
    #[derive(Debug, Copy, Clone, Deserialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    pub struct OverflowingStorageAddress(#[serde_as(as = "H256AsNoLeadingZerosHexStr")] pub H256);

    /// Contains parameters passed to `starknet_call`.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct Call {
        pub contract_address: ContractAddress,
        pub calldata: Vec<CallParam>,
        pub entry_point_selector: EntryPoint,
        /// EstimateFee hurry: it doesn't make any sense to use decimal numbers for one field
        #[serde(default)]
        #[serde_as(as = "Vec<CallSignatureElemAsDecimalStr>")]
        pub signature: Vec<CallSignatureElem>,
        /// EstimateFee hurry: max fee is needed if there's a signature
        #[serde_as(as = "FeeAsHexStr")]
        #[serde(default = "call_default_max_fee")]
        pub max_fee: Fee,
        /// EstimateFee hurry: transaction version might be interesting, might not be around for
        /// long
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default = "call_default_version")]
        pub version: TransactionVersion,
    }

    const fn call_default_max_fee() -> Fee {
        Call::DEFAULT_MAX_FEE
    }

    const fn call_default_version() -> TransactionVersion {
        Call::DEFAULT_VERSION
    }

    impl Call {
        pub const DEFAULT_MAX_FEE: Fee = Fee(web3::types::H128::zero());
        pub const DEFAULT_VERSION: TransactionVersion =
            TransactionVersion(web3::types::H256::zero());
    }

    /// This is what [`Call`] used to be, but is used in
    /// [`crate::rpc::api::RpcApi::add_invoke_transaction`] for example.
    ///
    /// It might be that [`Call`] and arguments of `addInvokeTransaction` could be unified in the
    /// future when the dust has settled on the implementation.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct ContractCall {
        pub contract_address: ContractAddress,
        pub calldata: Vec<CallParam>,
        pub entry_point_selector: EntryPoint,
    }

    /// Determines the type of response to block related queries.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
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
    #[skip_serializing_none]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
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
        pub page_size: usize,
        pub page_number: usize,
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    // At the moment both reply types are the same for get_code, hence the re-export
    use super::request::BlockResponseScope;
    use crate::{
        core::{
            CallParam, ClassHash, ConstructorParam, ContractAddress, EntryPoint, EventData,
            EventKey, Fee, GasPrice, GlobalRoot, SequencerAddress, StarknetBlockHash,
            StarknetBlockNumber, StarknetBlockTimestamp, StarknetTransactionHash, TransactionNonce,
            TransactionSignatureElem, TransactionVersion,
        },
        rpc::{
            api::RawBlock,
            serde::{FeeAsHexStr, GasPriceAsHexStr, TransactionVersionAsHexStr},
        },
        sequencer,
    };
    use serde::Serialize;
    use serde_with::{serde_as, skip_serializing_none};
    use stark_hash::StarkHash;
    use std::convert::From;

    /// L2 Block status as returned by the RPC API.
    #[derive(Copy, Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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

    impl From<sequencer::reply::Status> for BlockStatus {
        fn from(status: sequencer::reply::Status) -> Self {
            match status {
                // TODO verify this mapping with Starkware
                sequencer::reply::Status::AcceptedOnL1 => BlockStatus::AcceptedOnL1,
                sequencer::reply::Status::AcceptedOnL2 => BlockStatus::AcceptedOnL2,
                sequencer::reply::Status::NotReceived => BlockStatus::Rejected,
                sequencer::reply::Status::Pending => BlockStatus::Pending,
                sequencer::reply::Status::Received => BlockStatus::Pending,
                sequencer::reply::Status::Rejected => BlockStatus::Rejected,
                sequencer::reply::Status::Reverted => BlockStatus::Rejected,
                sequencer::reply::Status::Aborted => BlockStatus::Rejected,
            }
        }
    }

    /// Wrapper for transaction data returned in block related queries,
    /// chosen variant depends on [BlockResponseScope](crate::rpc::types::request::BlockResponseScope).
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    #[serde(untagged)]
    pub enum Transactions {
        // The larger variant, `FullWithReceipts` needs
        // to come __before__ `Full`  as it contains a structure
        // which has the same fields as `Full` plus some additional fields.
        // Which means that `serde` would always wrongly deserialize
        // to the smaller variant if the order here was swapped
        // (ie. smaller variant first, bigger next).
        FullWithReceipts(Vec<TransactionAndReceipt>),
        Full(Vec<Transaction>),
        HashesOnly(Vec<StarknetTransactionHash>),
    }

    /// L2 Block as returned by the RPC API.
    #[serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct Block {
        pub block_hash: Option<StarknetBlockHash>,
        pub parent_hash: StarknetBlockHash,
        pub block_number: Option<StarknetBlockNumber>,
        pub status: BlockStatus,
        pub sequencer: SequencerAddress,
        pub new_root: Option<GlobalRoot>,
        // FIXME: remove this field
        pub old_root: GlobalRoot,
        pub accepted_time: StarknetBlockTimestamp,
        #[serde_as(as = "GasPriceAsHexStr")]
        pub gas_price: GasPrice,
        pub transactions: Transactions,
    }

    impl Block {
        /// Constructs [Block] from [RawBlock]
        pub fn from_raw(block: RawBlock, transactions: Transactions) -> Self {
            Self {
                block_hash: Some(block.hash),
                parent_hash: block.parent_hash,
                block_number: Some(block.number),
                status: block.status,
                sequencer: block.sequencer,
                new_root: Some(block.root),
                old_root: block.parent_root,
                accepted_time: block.timestamp,
                gas_price: block.gas_price,
                transactions,
            }
        }

        /// Constructs [Block] from [sequencer's block representation](crate::sequencer::reply::Block)
        pub fn try_from_sequencer_scoped(
            block: sequencer::reply::MaybePendingBlock,
            scope: BlockResponseScope,
        ) -> Result<Self, TransactionAndReceiptMismatchError> {
            let transactions = match scope {
                BlockResponseScope::TransactionHashes => {
                    let hashes = block.transactions().iter().map(|t| t.hash()).collect();

                    Transactions::HashesOnly(hashes)
                }
                BlockResponseScope::FullTransactions => {
                    let transactions = block.transactions().iter().map(|t| t.into()).collect();
                    Transactions::Full(transactions)
                }
                BlockResponseScope::FullTransactionsAndReceipts => {
                    block
                        .transactions()
                        .iter()
                        .zip(block.receipts().iter())
                        .map(|(t, r)| {
                            let receipt = TransactionReceipt::with_block_status(
                                r.clone(),
                                block.status().into(),
                                t,
                            );
                            let txn: Transaction = t.into();
                            let result: Result<TransactionAndReceipt, TransactionAndReceiptMismatchError>  = (txn, receipt).try_into();
                            result
                        })
                        .collect::<Result<Vec<TransactionAndReceipt>, TransactionAndReceiptMismatchError>>()
                        .map(Transactions::FullWithReceipts)?
                }
            };

            use sequencer::reply::MaybePendingBlock;
            match block {
                MaybePendingBlock::Block(block) => Ok(Self {
                    block_hash: Some(block.block_hash),
                    parent_hash: block.parent_block_hash,
                    block_number: Some(block.block_number),
                    status: block.status.into(),
                    sequencer: block
                        .sequencer_address
                        // Default value for cairo <0.8.0 is 0
                        .unwrap_or(SequencerAddress(StarkHash::ZERO)),
                    new_root: Some(block.state_root),
                    old_root: GlobalRoot(StarkHash::ZERO),
                    accepted_time: block.timestamp,
                    gas_price: block
                        .gas_price
                        // Default value for cairo <0.8.2 is 0
                        .unwrap_or(GasPrice::ZERO),
                    transactions,
                }),
                MaybePendingBlock::Pending(pending) => Ok(Self {
                    block_hash: None,
                    parent_hash: pending.parent_hash,
                    block_number: None,
                    status: pending.status.into(),
                    sequencer: pending.sequencer_address,
                    new_root: None,
                    old_root: GlobalRoot(StarkHash::ZERO),
                    accepted_time: pending.timestamp,
                    gas_price: pending.gas_price,
                    transactions,
                }),
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
        InvalidContractClassHash = 28,
        PageSizeTooBig = 31,
        ContractError = 40,
        InvalidContractDefinition = 50,
    }

    /// We can have this equality and should have it in order to use it for tests. It is meant to
    /// be used when expecting that the rpc result is an error. The rpc result should first be
    /// accessed with [`Result::unwrap_err`], then compared to the expected [`ErrorCode`] with
    /// [`assert_eq!`].
    #[cfg(test)]
    impl PartialEq<jsonrpsee::core::error::Error> for ErrorCode {
        fn eq(&self, other: &jsonrpsee::core::error::Error) -> bool {
            use jsonrpsee::core::error::Error;
            use jsonrpsee::types::error::CallError;

            if let Error::Call(CallError::Custom(custom)) = other {
                // this is quite ackward dance to go back to error level then come back to the
                // custom error object. it however allows not having the json structure in two
                // places, and leaning on ErrorObject partialeq impl.
                let repr = match self {
                    ErrorCode::PageSizeTooBig => {
                        Error::from(crate::storage::EventFilterError::PageSizeTooBig(
                            crate::storage::StarknetEventsTable::PAGE_SIZE_LIMIT,
                        ))
                    }
                    other => Error::from(*other),
                };

                let repr = match repr {
                    Error::Call(CallError::Custom(repr)) => repr,
                    unexpected => unreachable!("using pathfinders ErrorCode to create jsonrpsee did not create a custom error: {unexpected:?}")
                };

                &repr == custom
            } else {
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
                28 => InvalidContractClassHash,
                31 => PageSizeTooBig,
                40 => ContractError,
                50 => InvalidContractDefinition,
                x => return Err(x),
            })
        }
    }

    impl ErrorCode {
        /// Returns the message specified in the openrpc api spec.
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
                ErrorCode::InvalidContractClassHash => {
                    "The supplied contract class hash is invalid or unknown"
                }
                ErrorCode::PageSizeTooBig => "Requested page size is too big",
                ErrorCode::ContractError => "Contract error",
                ErrorCode::InvalidContractDefinition => "Invalid contract definition",
            }
        }
    }

    impl std::string::ToString for ErrorCode {
        fn to_string(&self) -> String {
            self.as_str().to_owned()
        }
    }

    impl From<ErrorCode> for jsonrpsee::core::error::Error {
        fn from(ecode: ErrorCode) -> Self {
            use jsonrpsee::core::error::Error;
            use jsonrpsee::types::error::{CallError, ErrorObject};

            if ecode == ErrorCode::PageSizeTooBig {
                #[cfg(debug_assertions)]
                panic!("convert jsonrpsee::...::Error from EventFilterError to get error data");
            }

            let error = ecode as i32;
            Error::Call(CallError::Custom(ErrorObject::owned(
                error,
                ecode.to_string(),
                // this is insufficient in every situation (PageSizeTooBig)
                None::<()>,
            )))
        }
    }

    /// L2 state update as returned by the RPC API.
    #[skip_serializing_none]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct StateUpdate {
        /// None for `pending`
        #[serde(default)]
        block_hash: Option<StarknetBlockHash>,
        new_root: GlobalRoot,
        old_root: GlobalRoot,
        accepted_time: u64,
        state_diff: state_update::StateDiff,
    }

    /// State update related substructures.
    pub mod state_update {
        use crate::core::{ClassHash, ContractAddress, StorageAddress, StorageValue};
        use serde::Serialize;

        /// L2 state diff.
        #[derive(Clone, Debug, Serialize, PartialEq)]
        #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
        #[serde(deny_unknown_fields)]
        pub struct StateDiff {
            storage_diffs: Vec<StorageDiff>,
            contracts: Vec<Contract>,
        }

        /// L2 storage diff.
        #[derive(Clone, Debug, Serialize, PartialEq)]
        #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
        #[serde(deny_unknown_fields)]
        pub struct StorageDiff {
            address: ContractAddress,
            key: StorageAddress,
            value: StorageValue,
        }

        /// L2 contract data within state diff.
        #[derive(Clone, Debug, Serialize, PartialEq)]
        #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
        #[serde(deny_unknown_fields)]
        pub struct Contract {
            address: ContractAddress,
            contract_hash: ClassHash,
        }
    }

    /// L2 transaction as returned by the RPC API.
    ///
    /// Ideally this would be an internally tagged enum (where the "type" property
    /// contains the type of the transaction), but the OpenRPC specification
    /// doesn't have that. We're falling back to an untagged serde enum
    /// here and hope that the set of property names make each type unique...
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(untagged)]
    pub enum Transaction {
        Declare(DeclareTransaction),
        Invoke(InvokeTransaction),
        Deploy(DeployTransaction),
    }

    impl Transaction {
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Transaction::Declare(declare) => declare.common.txn_hash,
                Transaction::Invoke(invoke) => invoke.common.txn_hash,
                Transaction::Deploy(deploy) => deploy.txn_hash,
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonTransactionProperties {
        pub txn_hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareTransaction {
        #[serde(flatten)]
        pub common: CommonTransactionProperties,

        pub class_hash: ClassHash,
        pub sender_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransaction {
        #[serde(flatten)]
        pub common: CommonTransactionProperties,

        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub calldata: Vec<CallParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployTransaction {
        pub txn_hash: StarknetTransactionHash,

        pub contract_address: ContractAddress,
        pub class_hash: ClassHash,
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    impl TryFrom<sequencer::reply::Transaction> for Transaction {
        type Error = anyhow::Error;

        fn try_from(txn: sequencer::reply::Transaction) -> Result<Self, Self::Error> {
            let txn = txn
                .transaction
                .ok_or_else(|| anyhow::anyhow!("Transaction not found."))?;

            Ok(txn.into())
        }
    }

    impl From<sequencer::reply::transaction::Transaction> for Transaction {
        fn from(txn: sequencer::reply::transaction::Transaction) -> Self {
            Self::from(&txn)
        }
    }

    impl From<&sequencer::reply::transaction::Transaction> for Transaction {
        fn from(txn: &sequencer::reply::transaction::Transaction) -> Self {
            match txn {
                sequencer::reply::transaction::Transaction::Invoke(txn) => {
                    Self::Invoke(InvokeTransaction {
                        common: CommonTransactionProperties {
                            txn_hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            // no `version` in invoke transactions
                            version: TransactionVersion(Default::default()),
                            signature: txn.signature.clone(),
                            // no `nonce` in invoke transactions
                            nonce: TransactionNonce(Default::default()),
                        },
                        contract_address: txn.contract_address,
                        entry_point_selector: txn.entry_point_selector,
                        calldata: txn.calldata.clone(),
                    })
                }
                sequencer::reply::transaction::Transaction::Declare(txn) => {
                    Self::Declare(DeclareTransaction {
                        common: CommonTransactionProperties {
                            txn_hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            version: txn.version,
                            signature: txn.signature.clone(),
                            nonce: txn.nonce,
                        },
                        class_hash: txn.class_hash,
                        sender_address: txn.sender_address,
                    })
                }
                sequencer::reply::transaction::Transaction::Deploy(txn) => {
                    Self::Deploy(DeployTransaction {
                        txn_hash: txn.transaction_hash,
                        contract_address: txn.contract_address,
                        class_hash: txn.class_hash,
                        constructor_calldata: txn.constructor_calldata.clone(),
                    })
                }
            }
        }
    }

    /// L2 transaction receipt as returned by the RPC API.
    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(untagged)]
    pub enum TransactionReceipt {
        Invoke(InvokeTransactionReceipt),
        // We can't differentiate between declare and deploy in an untagged enum: they
        // have the same properties in the JSON.
        DeclareOrDeploy(DeclareOrDeployTransactionReceipt),
    }

    impl TransactionReceipt {
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Self::Invoke(tx) => tx.common.txn_hash,
                Self::DeclareOrDeploy(tx) => tx.common.txn_hash,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,

        pub messages_sent: Vec<transaction_receipt::MessageToL1>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub l1_origin_message: Option<transaction_receipt::MessageToL2>,
        pub events: Vec<transaction_receipt::Event>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonTransactionReceiptProperties {
        pub txn_hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub actual_fee: Fee,
        pub status: TransactionStatus,
        #[serde(
            default,
            rename = "statusData",
            skip_serializing_if = "Option::is_none"
        )]
        pub status_data: Option<String>,
    }

    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareOrDeployTransactionReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionReceiptProperties,
    }

    impl TransactionReceipt {
        pub fn with_block_status(
            receipt: sequencer::reply::transaction::Receipt,
            status: BlockStatus,
            transaction: &sequencer::reply::transaction::Transaction,
        ) -> Self {
            match transaction {
                sequencer::reply::transaction::Transaction::Declare(_)
                | sequencer::reply::transaction::Transaction::Deploy(_) => {
                    Self::DeclareOrDeploy(DeclareOrDeployTransactionReceipt {
                        common: CommonTransactionReceiptProperties {
                            txn_hash: receipt.transaction_hash,
                            actual_fee: receipt
                                .actual_fee
                                .unwrap_or_else(|| Fee(Default::default())),
                            status: status.into(),
                            // TODO: at the moment not available in sequencer replies
                            status_data: None,
                        },
                    })
                }
                sequencer::reply::transaction::Transaction::Invoke(_) => {
                    Self::Invoke(InvokeTransactionReceipt {
                        common: CommonTransactionReceiptProperties {
                            txn_hash: receipt.transaction_hash,
                            actual_fee: receipt
                                .actual_fee
                                .unwrap_or_else(|| Fee(Default::default())),
                            status: status.into(),
                            // TODO: at the moment not available in sequencer replies
                            status_data: None,
                        },
                        messages_sent: receipt
                            .l2_to_l1_messages
                            .into_iter()
                            .map(transaction_receipt::MessageToL1::from)
                            .collect(),
                        l1_origin_message: receipt
                            .l1_to_l2_consumed_message
                            .map(transaction_receipt::MessageToL2::from),
                        events: receipt
                            .events
                            .into_iter()
                            .map(transaction_receipt::Event::from)
                            .collect(),
                    })
                }
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
        use serde::Serialize;
        use serde_with::serde_as;
        use std::convert::From;

        /// Message sent from L2 to L1.
        #[serde_as]
        #[derive(Clone, Debug, Serialize, PartialEq)]
        #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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
        #[derive(Clone, Debug, Serialize, PartialEq)]
        #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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
        #[derive(Clone, Debug, Serialize, PartialEq)]
        #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
        #[serde(deny_unknown_fields)]
        pub struct Event {
            pub from_address: ContractAddress,
            pub keys: Vec<EventKey>,
            pub data: Vec<EventData>,
        }

        impl From<crate::sequencer::reply::transaction::Event> for Event {
            fn from(e: crate::sequencer::reply::transaction::Event) -> Self {
                Self {
                    from_address: e.from_address,
                    keys: e.keys,
                    data: e.data,
                }
            }
        }
    }

    /// Used in [Block](crate::rpc::types::reply::Block) when the requested scope of
    /// reply is [BlockResponseScope::FullTransactionsAndReceipts](crate::rpc::types::request::BlockResponseScope).
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(untagged)]
    pub enum TransactionAndReceipt {
        Declare(DeclareTransactionAndReceipt),
        Invoke(InvokeTransactionAndReceipt),
        Deploy(DeployTransactionAndReceipt),
    }

    impl TransactionAndReceipt {
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                TransactionAndReceipt::Declare(declare) => declare.common.txn_hash,
                TransactionAndReceipt::Invoke(invoke) => invoke.common.txn_hash,
                TransactionAndReceipt::Deploy(deploy) => deploy.txn_hash,
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareTransactionAndReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionAndReceiptProperties,

        pub class_hash: ClassHash,
        pub sender_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransactionAndReceipt {
        #[serde(flatten)]
        pub common: CommonTransactionAndReceiptProperties,

        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub calldata: Vec<CallParam>,

        pub messages_sent: Vec<transaction_receipt::MessageToL1>,
        // Important!
        // #[skip_serializing_none] does not work with #[serde(flatten)]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub l1_origin_message: Option<transaction_receipt::MessageToL2>,
        pub events: Vec<transaction_receipt::Event>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployTransactionAndReceipt {
        // We cannot use [CommonTransactionAndReceiptProperties] here because
        // DeployTransaction doesn't have all common properties.
        // Transaction
        pub txn_hash: StarknetTransactionHash,

        // Receipt
        // FIXME: update this once we know the deploy receipt type
        #[serde_as(as = "FeeAsHexStr")]
        pub actual_fee: Fee,
        pub status: TransactionStatus,
        // Important!
        // #[skip_serializing_none] does not work with #[serde(flatten)]
        #[serde(
            default,
            rename = "statusData",
            skip_serializing_if = "Option::is_none"
        )]
        pub status_data: Option<String>,

        pub contract_address: ContractAddress,
        pub class_hash: ClassHash,
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonTransactionAndReceiptProperties {
        // Transaction
        pub txn_hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        // Receipt
        #[serde_as(as = "FeeAsHexStr")]
        pub actual_fee: Fee,
        pub status: TransactionStatus,
        // Important!
        // #[skip_serializing_none] does not work with #[serde(flatten)]
        #[serde(
            default,
            rename = "statusData",
            skip_serializing_if = "Option::is_none"
        )]
        pub status_data: Option<String>,
    }

    impl
        From<(
            CommonTransactionProperties,
            CommonTransactionReceiptProperties,
        )> for CommonTransactionAndReceiptProperties
    {
        fn from(
            both: (
                CommonTransactionProperties,
                CommonTransactionReceiptProperties,
            ),
        ) -> Self {
            let (t, r) = both;

            assert_eq!(t.txn_hash, r.txn_hash);

            Self {
                txn_hash: t.txn_hash,
                max_fee: t.max_fee,
                version: t.version,
                signature: t.signature,
                nonce: t.nonce,
                actual_fee: r.actual_fee,
                status: r.status,
                status_data: r.status_data,
            }
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("transaction type does not match transaction receipt type")]
    pub struct TransactionAndReceiptMismatchError;

    impl TryFrom<(Transaction, TransactionReceipt)> for TransactionAndReceipt {
        type Error = TransactionAndReceiptMismatchError;

        fn try_from(both: (Transaction, TransactionReceipt)) -> Result<Self, Self::Error> {
            let (t, r) = both;

            match (t, r) {
                (Transaction::Declare(t), TransactionReceipt::DeclareOrDeploy(r)) => Ok(
                    TransactionAndReceipt::Declare(DeclareTransactionAndReceipt {
                        common: (t.common, r.common).into(),
                        class_hash: t.class_hash,
                        sender_address: t.sender_address,
                    }),
                ),
                (Transaction::Deploy(t), TransactionReceipt::DeclareOrDeploy(r)) => {
                    Ok(TransactionAndReceipt::Deploy(DeployTransactionAndReceipt {
                        txn_hash: t.txn_hash,
                        actual_fee: r.common.actual_fee,
                        status: r.common.status,
                        status_data: r.common.status_data,
                        contract_address: t.contract_address,
                        class_hash: t.class_hash,
                        constructor_calldata: t.constructor_calldata,
                    }))
                }
                (Transaction::Invoke(t), TransactionReceipt::Invoke(r)) => {
                    Ok(TransactionAndReceipt::Invoke(InvokeTransactionAndReceipt {
                        common: (t.common, r.common).into(),
                        contract_address: t.contract_address,
                        entry_point_selector: t.entry_point_selector,
                        calldata: t.calldata,
                        messages_sent: r.messages_sent,
                        l1_origin_message: r.l1_origin_message,
                        events: r.events,
                    }))
                }
                _ => Err(TransactionAndReceiptMismatchError),
            }
        }
    }

    /// Represents transaction status.
    #[derive(Copy, Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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

    impl From<sequencer::reply::Status> for TransactionStatus {
        fn from(status: sequencer::reply::Status) -> Self {
            match status {
                // TODO verify this mapping with Starkware
                sequencer::reply::Status::AcceptedOnL1 => TransactionStatus::AcceptedOnL1,
                sequencer::reply::Status::AcceptedOnL2 => TransactionStatus::AcceptedOnL2,
                sequencer::reply::Status::NotReceived => TransactionStatus::Unknown,
                sequencer::reply::Status::Pending => TransactionStatus::Pending,
                sequencer::reply::Status::Received => TransactionStatus::Received,
                sequencer::reply::Status::Rejected => TransactionStatus::Rejected,
                sequencer::reply::Status::Reverted => TransactionStatus::Unknown,
                sequencer::reply::Status::Aborted => TransactionStatus::Unknown,
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
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(untagged)]
    pub enum Syncing {
        False(bool),
        Status(syncing::Status),
    }

    impl std::fmt::Display for Syncing {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Syncing::False(_) => f.write_str("false"),
                Syncing::Status(status) => {
                    write!(f, "{}", status)
                }
            }
        }
    }

    /// Starknet's syncing status substructures.
    pub mod syncing {
        use crate::{
            core::{StarknetBlockHash, StarknetBlockNumber},
            rpc::serde::StarknetBlockNumberAsHexStr,
        };
        use serde::Serialize;
        use serde_with::serde_as;

        /// Represents Starknet node syncing status.
        #[derive(Copy, Clone, Debug, PartialEq, Serialize)]
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
        #[derive(Clone, Copy, Serialize, PartialEq)]
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
                write!(fmt, "({}, {})", self.hash.0, self.number.0)
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
                use stark_hash::StarkHash;
                NumberedBlock {
                    hash: StarknetBlockHash(StarkHash::from_hex_str(h).unwrap()),
                    number: StarknetBlockNumber(n),
                }
            }
        }
    }

    #[test]
    fn roundtrip_syncing() {
        use syncing::NumberedBlock;
        let examples = [
            (line!(), "false", Syncing::False(false)),
            // this shouldn't exist but it exists now
            (line!(), "true", Syncing::False(true)),
            (
                line!(),
                r#"{"starting_block_hash":"0xa","starting_block_num":"0x1","current_block_hash":"0xb","current_block_num":"0x2","highest_block_hash":"0xc","highest_block_num":"0x3"}"#,
                Syncing::Status(syncing::Status {
                    starting: NumberedBlock::from(("a", 1)),
                    current: NumberedBlock::from(("b", 2)),
                    highest: NumberedBlock::from(("c", 3)),
                }),
            ),
        ];

        for (line, input, expected) in examples {
            let parsed = serde_json::from_str::<Syncing>(input).unwrap();
            let output = serde_json::to_string(&parsed).unwrap();

            assert_eq!(parsed, expected, "example from line {}", line);
            assert_eq!(&output, input, "example from line {}", line);
        }
    }

    /// Describes an emitted event returned by starknet_getEvents
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
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
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct GetEventsResult {
        pub events: Vec<EmittedEvent>,
        pub page_number: usize,
        pub is_last_page: bool,
    }

    // Result type for starknet_addInvokeTransaction
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionResult {
        pub transaction_hash: StarknetTransactionHash,
    }

    // Result type for starknet_addDeclareTransaction
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionResult {
        pub transaction_hash: StarknetTransactionHash,
        pub class_hash: ClassHash,
    }

    // Result type for starknet_addDeployTransaction
    #[derive(Clone, Debug, Serialize, PartialEq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransactionResult {
        pub transaction_hash: StarknetTransactionHash,
        pub contract_address: ContractAddress,
    }

    /// Return type of transaction fee estimation
    #[serde_as]
    #[derive(Clone, Debug, serde::Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct FeeEstimate {
        /// The Ethereum gas cost of the transaction
        #[serde_as(as = "crate::rpc::serde::H256AsHexStr")]
        #[serde(rename = "gas_consumed")]
        pub consumed: web3::types::H256,
        /// The gas price (in gwei) that was used in the cost estimation (input to fee estimation)
        #[serde_as(as = "crate::rpc::serde::H256AsHexStr")]
        pub gas_price: web3::types::H256,
        /// The estimated fee for the transaction (in gwei), product of gas_consumed and gas_price
        #[serde_as(as = "crate::rpc::serde::H256AsHexStr")]
        #[serde(rename = "overall_fee")]
        pub fee: web3::types::H256,
    }
}
