//! Structures used for deserializing replies from Starkware's sequencer REST API.
use crate::sequencer::serde::{H256AsRelaxedHexStr, U256AsBigDecimal, U256AsDecimalStr};
use serde::Deserialize;
use std::collections::HashMap;
use web3::types::{H256, U256};

/// Used to deserialize replies to [Client::block](crate::sequencer::Client::block) and
/// [Client::latest_block](crate::sequencer::Client::latest_block).
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    #[serde_as(as = "U256AsBigDecimal")]
    pub block_id: U256,
    #[serde_as(as = "U256AsBigDecimal")]
    pub previous_block_id: U256,
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

/// Used to deserialize a reply from [Client::call](crate::sequencer::Client::call).
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Call {
    #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
    pub result: Vec<H256>,
}

/// Used to deserialize a reply from [Client::code](crate::sequencer::Client::code).
#[serde_with::serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub abi: Vec<code::Abi>,
    #[serde_as(as = "Vec<H256AsRelaxedHexStr>")]
    pub bytecode: Vec<H256>,
}

/// Types used when deserializing L2 contract related data.
pub mod code {
    use serde::Deserialize;

    /// Represents deserialized L2 contract Application Blockchain Interface element.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
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
        use serde::Deserialize;

        /// Represents deserialized L2 contract ABI input element.
        #[derive(Clone, Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Input {
            pub name: String,
            pub r#type: String,
        }

        /// Represents deserialized L2 contract ABI output element.
        #[derive(Clone, Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Output {
            pub name: String,
            pub r#type: String,
        }
    }
}

/// Used to deserialize a reply from [Client::transaction](crate::sequencer::Client::transaction).
#[serde_with::serde_as]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    #[serde_as(as = "U256AsBigDecimal")]
    pub block_id: U256,
    #[serde_as(as = "U256AsBigDecimal")]
    pub block_number: U256,
    pub status: transaction::Status,
    #[serde(rename = "transaction")]
    pub source: transaction::Source,
    #[serde_as(as = "U256AsBigDecimal")]
    pub transaction_id: U256,
    pub transaction_index: u64,
}

/// Used to deserialize a reply from [Client::transaction_status](crate::sequencer::Client::transaction_status).
#[serde_with::serde_as]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    #[serde_as(as = "U256AsBigDecimal")]
    pub block_id: U256,
    pub tx_status: transaction::Status,
}

/// Types used when deserializing L2 transaction related data.
pub mod transaction {
    use crate::sequencer::serde::{
        H160AsRelaxedHexStr, H256AsRelaxedHexStr, U256AsBigDecimal, U256AsDecimalStr,
    };
    use serde::Deserialize;
    use web3::types::{H160, H256, U256};

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
    }

    /// Represents deserialized L2 to L1 message.
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
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
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde_as(as = "U256AsBigDecimal")]
        pub block_id: U256,
        #[serde_as(as = "U256AsBigDecimal")]
        pub block_number: U256,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub status: Status,
        #[serde_as(as = "U256AsBigDecimal")]
        pub transaction_id: U256,
        pub transaction_index: u64,
    }

    /// Represents deserialized object containing L2 contract address and transaction type.
    #[serde_with::serde_as]
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Source {
        #[serde_as(as = "H256AsRelaxedHexStr")]
        pub contract_address: H256,
        pub r#type: Type,
    }

    /// L2 transaction status values.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
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
    #[serde_with::serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
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
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum Type {
        #[serde(rename = "DEPLOY")]
        Deploy,
        #[serde(rename = "INVOKE_FUNCTION")]
        InvokeFunction,
    }
}
