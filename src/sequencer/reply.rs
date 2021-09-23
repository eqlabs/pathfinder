//! Structures used for deserializing replies from Starkware's sequencer REST API.
//! __Warning!__Prone to change as the structures are solely based on reverse
//! engineering raw API replies!
use crate::sequencer::deserialize::{
    from_decimal, from_decimal_array, from_decimal_str_keyed_map, from_hex_str,
};
use serde::Deserialize;
use std::collections::HashMap;
use web3::types::{H256, U256};

/// Used to deserialize replies to [Client::block](crate::sequencer::Client::block) and
/// [Client::latest_block](crate::sequencer::Client::latest_block).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Block {
    #[serde(deserialize_with = "from_decimal")]
    pub block_id: U256,
    #[serde(deserialize_with = "from_decimal")]
    pub previous_block_id: U256,
    #[serde(deserialize_with = "from_decimal")]
    pub sequence_number: U256,
    #[serde(deserialize_with = "from_hex_str")]
    pub state_root: H256,
    pub status: block::Status,
    pub timestamp: u64,
    #[serde(deserialize_with = "from_decimal_str_keyed_map")]
    pub transaction_receipts: HashMap<U256, transaction::Receipt>,
    #[serde(deserialize_with = "from_decimal_str_keyed_map")]
    pub transactions: HashMap<U256, transaction::Transaction>,
}

/// Types used when deserializing L2 block related data.
pub mod block {
    pub type Status = super::transaction::Status;
}

/// Used to deserialize a reply from [Client::call](crate::sequencer::Client::call).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Call {
    #[serde(deserialize_with = "from_decimal_array")]
    pub result: Vec<U256>,
}

/// Used to deserialize a reply from [Client::code](crate::sequencer::Client::code).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Code {
    pub abi: Vec<code::Abi>,
    #[serde(deserialize_with = "from_decimal_array")]
    pub bytecode: Vec<U256>,
}

/// Types used when deserializing L2 contract related data.
pub mod code {
    use serde::Deserialize;

    /// Represents deserialized L2 contract Application Blockchain Interface element.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
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
        pub struct Input {
            pub name: String,
            pub r#type: String,
        }

        /// Represents deserialized L2 contract ABI output element.
        #[derive(Clone, Debug, Deserialize, PartialEq)]
        pub struct Output {
            pub name: String,
            pub r#type: String,
        }
    }
}

/// Used to deserialize a reply from [Client::transaction](crate::sequencer::Client::transaction).
#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub struct Transaction {
    #[serde(flatten)]
    pub common: transaction::Common,
    #[serde(rename = "transaction")]
    pub source: transaction::Source,
}

/// Used to deserialize a reply from [Client::transaction_status](crate::sequencer::Client::transaction_status).
#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
pub struct TransactionStatus {
    #[serde(deserialize_with = "from_decimal")]
    pub block_id: U256,
    pub tx_status: transaction::Status,
}

/// Types used when deserializing L2 transaction related data.
pub mod transaction {
    use crate::sequencer::deserialize::{
        from_decimal, from_decimal_str_array, from_hex_str, from_optional_decimal_str_array,
        from_optional_hex_str,
    };
    use serde::Deserialize;
    use web3::types::{H160, H256, U256};

    /// Represents deserialized common L2 transaction data used in more than one transaction related struct.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    pub struct Common {
        #[serde(deserialize_with = "from_decimal")]
        pub block_id: U256,
        #[serde(deserialize_with = "from_decimal")]
        pub block_number: U256,
        pub status: Status,
        #[serde(deserialize_with = "from_decimal")]
        pub transaction_id: U256,
        pub transaction_index: u64,
    }

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
    }

    /// Represents deserialized L2 to L1 message.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    pub struct L2ToL1Message {
        #[serde(deserialize_with = "from_hex_str")]
        pub from_address: H256,
        #[serde(deserialize_with = "from_decimal_str_array")]
        pub payload: Vec<U256>,
        #[serde(deserialize_with = "from_hex_str")]
        pub to_address: H160,
    }

    /// Represents deserialized L2 transaction receipt data.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    pub struct Receipt {
        #[serde(flatten)]
        pub common: Common,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
    }

    /// Represents deserialized object containing L2 contract address and transaction type.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    pub struct Source {
        #[serde(deserialize_with = "from_hex_str")]
        pub contract_address: H256,
        pub r#type: Type,
    }

    /// L2 transaction status values.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
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
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    pub struct Transaction {
        #[serde(deserialize_with = "from_optional_decimal_str_array")]
        #[serde(default)]
        pub calldata: Option<Vec<U256>>,
        #[serde(deserialize_with = "from_hex_str")]
        pub contract_address: H256,
        #[serde(deserialize_with = "from_optional_hex_str")]
        #[serde(default)]
        pub entry_point_selector: Option<H256>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        pub r#type: Type,
    }

    /// Describes L2 transaction types.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    pub enum Type {
        #[serde(rename = "DEPLOY")]
        Deploy,
        #[serde(rename = "INVOKE_FUNCTION")]
        InvokeFunction,
    }
}
