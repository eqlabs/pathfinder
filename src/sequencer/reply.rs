//! Structures used for deserializing replies from Starkware's sequencer REST API.
use crate::sequencer::serde::{H256AsRelaxedHexStr, U256AsBigDecimal, U256AsDecimalStr};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, DefaultOnError};
use std::{collections::HashMap, convert::TryFrom};
use web3::types::{H256, U256};

/// Used to deserialize replies to [Client::block](crate::sequencer::Client::block) and
/// [Client::latest_block](crate::sequencer::Client::latest_block).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockReply {
    Block(Block),
    Error(starknet::Error),
}

impl TryFrom<BlockReply> for Block {
    type Error = anyhow::Error;

    fn try_from(value: BlockReply) -> Result<Self, Self::Error> {
        match value {
            BlockReply::Block(b) => Ok(b),
            BlockReply::Error(e) => Err(anyhow::Error::new(e)),
        }
    }
}

/// Actual block data from [BlockReply].
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    #[serde_as(as = "U256AsBigDecimal")]
    pub block_id: U256,
    #[serde_as(as = "DefaultOnError<Option<U256AsBigDecimal>>")]
    #[serde(default)]
    pub previous_block_id: Option<U256>,
    #[serde_as(as = "U256AsBigDecimal")]
    pub sequence_number: U256,
    #[serde_as(as = "H256AsRelaxedHexStr")]
    pub state_root: H256,
    pub status: block::Status,
    pub timestamp: u64,
    #[serde_as(as = "HashMap<U256AsDecimalStr, _>")]
    pub transaction_receipts: HashMap<U256, transaction::Receipt>,
    #[serde_as(as = "HashMap<U256AsDecimalStr, _>")]
    pub transactions: HashMap<U256, transaction::Transaction>,
}

/// Types used when deserializing L2 block related data.
pub mod block {
    pub type Status = super::transaction::Status;
}

// /// Used to deserialize a reply from [Client::call](crate::sequencer::Client::call).
// #[serde_as]
// #[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
// #[serde(untagged)]
// #[serde(deny_unknown_fields)]
// pub enum CallReply {
//     Call(#[serde_as(as = "Vec<H256AsRelaxedHexStr>")] Vec<H256>),
//     Error(starknet::Error),
// }

// impl TryFrom<CallReply> for Vec<H256> {
//     type Error = anyhow::Error;

//     fn try_from(value: CallReply) -> Result<Self, Self::Error> {
//         match value {
//             CallReply::Call(c) => Ok(c),
//             CallReply::Error(e) => Err(anyhow::Error::new(e)),
//         }
//     }
// }

// /// Actual call data from [CallReply].
// #[serde_as]
// #[skip_serializing_none]
// #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
// #[serde(deny_unknown_fields)]
// pub struct Call(#[serde_as(as = "Vec<H256AsRelaxedHexStr>")] Vec<H256>);

/// Used to deserialize a reply from [Client::call](crate::sequencer::Client::call).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum CallReply {
    Call(Call),
    Error(starknet::Error),
}

impl TryFrom<CallReply> for Call {
    type Error = anyhow::Error;

    fn try_from(value: CallReply) -> Result<Self, Self::Error> {
        match value {
            CallReply::Call(c) => Ok(c),
            CallReply::Error(e) => Err(anyhow::Error::new(e)),
        }
    }
}

/// Actual call data from [CallReply].
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Call {
    #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
    result: Vec<H256>,
}

/// Types used when deserializing L2 call related data.
pub mod call {
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// Describes problems encountered during some of call failures .
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Problems {
        #[serde_as(as = "HashMap<_, _>")]
        pub calldata: HashMap<u64, Vec<String>>,
    }
}

/// Used to deserialize a reply from [Client::code](crate::sequencer::Client::code).
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum CodeReply {
    Code(Code),
    Error(starknet::Error),
}

impl TryFrom<CodeReply> for Code {
    type Error = anyhow::Error;

    fn try_from(value: CodeReply) -> Result<Self, Self::Error> {
        match value {
            CodeReply::Code(c) => Ok(c),
            CodeReply::Error(e) => Err(anyhow::Error::new(e)),
        }
    }
}

/// Actual code data from [CodeReply].
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub abi: Vec<code::Abi>,
    #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
    pub bytecode: Vec<H256>,
}

/// Types used when deserializing L2 contract related data.
pub mod code {
    use serde::{Deserialize, Serialize};
    use serde_with::skip_serializing_none;

    /// Represents deserialized L2 contract Application Blockchain Interface element.
    #[skip_serializing_none]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Abi {
        pub inputs: Vec<abi::Input>,
        pub name: String,
        pub outputs: Vec<abi::Output>,
        pub r#type: String,
        #[serde(rename = "stateMutability")]
        #[serde(default)]
        pub state_mutability: Option<String>,
    }

    /// Types used when deserializing L2 contract ABI related data.
    pub mod abi {
        use serde::{Deserialize, Serialize};

        /// Represents deserialized L2 contract ABI input element.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Input {
            pub name: String,
            pub r#type: String,
        }

        /// Represents deserialized L2 contract ABI output element.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Output {
            pub name: String,
            pub r#type: String,
        }
    }
}

pub mod starknet {
    use serde::{Deserialize, Serialize};
    use serde_with::skip_serializing_none;

    /// Used for deserializing specific Starknet sequencer error data.
    #[skip_serializing_none]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    pub struct Error {
        pub code: ErrorCode,
        pub message: String,
        pub problems: Option<super::call::Problems>,
    }

    impl std::error::Error for Error {}

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    /// Represents error codes reported by the sequencer.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum ErrorCode {
        #[serde(rename = "StarknetErrorCode.BLOCK_NOT_FOUND")]
        BlockNotFound,
        #[serde(rename = "StarknetErrorCode.ENTRY_POINT_NOT_FOUND_IN_CONTRACT")]
        EntryPointNotFound,
        #[serde(rename = "StarknetErrorCode.OUT_OF_RANGE_CONTRACT_ADDRESS")]
        OutOfRangeContractAddress,
        #[serde(rename = "StarknetErrorCode.OUT_OF_RANGE_CONTRACT_STORAGE_KEY")]
        OutOfRangeStorageKey,
        #[serde(rename = "StarkErrorCode.SCHEMA_VALIDATION_ERROR")]
        SchemaValidationError,
        #[serde(rename = "StarknetErrorCode.TRANSACTION_FAILED")]
        TransactionFailed,
        #[serde(rename = "StarknetErrorCode.UNINITIALIZED_CONTRACT")]
        UninitializedContract,
    }
}

/// Used to deserialize a reply from [Client::transaction](crate::sequencer::Client::transaction).
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    #[serde_as(as = "Option<U256AsBigDecimal>")]
    #[serde(default)]
    pub block_id: Option<U256>,
    #[serde_as(as = "Option<U256AsBigDecimal>")]
    #[serde(default)]
    pub block_number: Option<U256>,
    pub status: transaction::Status,
    #[serde(default)]
    pub transaction: Option<transaction::Transaction>,
    #[serde(default)]
    pub transaction_failure_reason: Option<transaction::Failure>,
    #[serde_as(as = "U256AsBigDecimal")]
    pub transaction_id: U256,
    #[serde(default)]
    pub transaction_index: Option<u64>,
}

/// Used to deserialize a reply from [Client::transaction_status](crate::sequencer::Client::transaction_status).
#[serde_as]
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    #[serde_as(as = "Option<U256AsBigDecimal>")]
    #[serde(default)]
    pub block_id: Option<U256>,
    #[serde(default)]
    pub tx_status: Option<transaction::Status>,
    #[serde(default)]
    pub tx_failure_reason: Option<transaction::Failure>,
}

/// Types used when deserializing L2 transaction related data.
pub mod transaction {
    use crate::sequencer::serde::{
        H160AsRelaxedHexStr, H256AsRelaxedHexStr, U256AsBigDecimal, U256AsDecimalStr,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::{serde_as, skip_serializing_none};
    use web3::types::{H160, H256, U256};

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    /// Represents deserialized L1 to L2 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct L1ToL2Message {
        #[serde_as(as = "H160AsRelaxedHexStr")]
        pub from_address: H160,
        #[serde_as(as = "Vec<U256AsDecimalStr>")]
        pub payload: Vec<U256>,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub selector: H256,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub to_address: H256,
    }

    /// Represents deserialized L2 to L1 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct L2ToL1Message {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub from_address: H256,
        #[serde_as(as = "Vec<U256AsDecimalStr>")]
        pub payload: Vec<U256>,
        #[serde_as(as = "H160AsRelaxedHexStr")]
        pub to_address: H160,
    }

    /// Represents deserialized L2 transaction receipt data.
    #[serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde_as(as = "U256AsBigDecimal")]
        pub block_id: U256,
        #[serde_as(as = "U256AsBigDecimal")]
        pub block_number: U256,
        #[serde(default)]
        pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub status: Status,
        #[serde_as(as = "U256AsBigDecimal")]
        pub transaction_id: U256,
        pub transaction_index: u64,
    }

    /// Represents deserialized object containing L2 contract address and transaction type.
    #[serde_as]
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Source {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub contract_address: H256,
        pub r#type: Type,
    }

    /// L2 transaction status values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum Status {
        #[serde(rename = "NOT_RECEIVED")]
        NotReceived,
        #[serde(rename = "RECEIVED")]
        Received,
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "REJECTED")]
        Rejected,
        #[serde(rename = "ACCEPTED_ONCHAIN")]
        AcceptedOnChain,
    }

    /// Represents deserialized L2 transaction data.
    #[serde_as]
    #[skip_serializing_none]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Transaction {
        #[serde(default)]
        #[serde_as(as = "Option<Vec<U256AsDecimalStr>>")]
        pub calldata: Option<Vec<U256>>,
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub contract_address: H256,
        #[serde_as(as = "Option<H256AsRelaxedHexStr>")]
        #[serde(default)]
        pub entry_point_selector: Option<H256>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        pub r#type: Type,
    }

    /// Describes L2 transaction types.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum Type {
        #[serde(rename = "DEPLOY")]
        Deploy,
        #[serde(rename = "INVOKE_FUNCTION")]
        InvokeFunction,
    }

    /// Describes L2 transaction failure details.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Failure {
        pub code: String,
        pub error_message: String,
        #[serde_as(as = "U256AsBigDecimal")]
        pub tx_id: U256,
    }
}
