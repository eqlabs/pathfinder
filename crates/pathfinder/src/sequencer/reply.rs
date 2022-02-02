//! Structures used for deserializing replies from Starkware's sequencer REST API.
use crate::core::{CallResultValue, GlobalRoot, StarknetBlockHash, StarknetBlockNumber};
use pedersen::StarkHash;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Used to deserialize replies to [Client::block_by_hash](crate::sequencer::Client::block_by_hash) and
/// [Client::block_by_number](crate::sequencer::Client::block_by_number).
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    #[serde(default)]
    pub block_hash: Option<StarknetBlockHash>,
    #[serde(default)]
    pub block_number: Option<StarknetBlockNumber>,
    pub parent_block_hash: StarknetBlockHash,
    #[serde(default)]
    pub state_root: Option<GlobalRoot>,
    pub status: Status,
    pub timestamp: u64,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
}

/// Block and transaction status values.
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
    #[serde(rename = "ACCEPTED_ON_L1")]
    AcceptedOnL1,
    #[serde(rename = "ACCEPTED_ON_L2")]
    AcceptedOnL2,
    #[serde(rename = "REVERTED")]
    Reverted,
    #[serde(rename = "ABORTED")]
    Aborted,
}

/// Used to deserialize a reply from [Client::call](crate::sequencer::Client::call).
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub result: Vec<CallResultValue>,
}

/// Types used when deserializing L2 call related data.
pub mod call {
    use serde::Deserialize;
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// Describes problems encountered during some of call failures .
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Problems {
        #[serde_as(as = "HashMap<_, _>")]
        pub calldata: HashMap<u64, Vec<String>>,
    }
}

/// Used to deserialize a reply from [Client::code](crate::sequencer::Client::code).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub abi: Box<serde_json::value::RawValue>,
    pub bytecode: Vec<StarkHash>,
}

/// Types used when deserializing L2 contract related data.
pub mod code {
    use serde::{Deserialize, Serialize};

    /// Represents deserialized L2 contract Application Blockchain Interface element.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Abi {
        #[serde(default)]
        pub inputs: Option<Vec<abi::Input>>,
        #[serde(default)]
        pub members: Option<Vec<abi::Member>>,
        pub name: String,
        #[serde(default)]
        pub outputs: Option<Vec<abi::Output>>,
        pub r#type: String,
        #[serde(default)]
        pub size: Option<u64>,
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

        /// Represents deserialized L2 contract ABI member element.
        #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct Member {
            pub name: String,
            pub offset: u64,
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

/// Used to deserialize replies to [Client::transaction](crate::sequencer::Client::transaction).
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    #[serde(default)]
    pub block_hash: Option<StarknetBlockHash>,
    #[serde(default)]
    pub block_number: Option<StarknetBlockNumber>,
    pub status: Status,
    #[serde(default)]
    pub transaction: Option<transaction::Transaction>,
    #[serde(default)]
    pub transaction_index: Option<u64>,
}

/// Used to deserialize replies to [Client::transaction_status](crate::sequencer::Client::transaction_status).
#[serde_as]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    #[serde(default)]
    pub block_hash: Option<StarknetBlockHash>,
    pub tx_status: Status,
}

/// Types used when deserializing L2 transaction related data.
pub mod transaction {
    use crate::{
        core::{
            CallParam, ConstructorParam, ContractAddress, ContractAddressSalt, EntryPoint,
            EthereumAddress, EventData, EventKey, L1ToL2MessageNonce, L1ToL2MessagePayloadElem,
            L2ToL1MessagePayloadElem, StarknetTransactionHash, StarknetTransactionIndex,
            TransactionSignatureElem,
        },
        rpc::serde::{
            CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
            EventDataAsDecimalStr, EventKeyAsDecimalStr, L1ToL2MessagePayloadElemAsDecimalStr,
            L2ToL1MessagePayloadElemAsDecimalStr, TransactionSignatureElemAsDecimalStr,
        },
    };
    use serde::Deserialize;
    use serde_with::serde_as;

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionResources {
        builtin_instance_counter: execution_resources::BuiltinInstanceCounter,
        n_steps: u64,
        n_memory_holes: u64,
    }

    /// Types used when deserializing L2 execution resources related data.
    pub mod execution_resources {
        use serde::Deserialize;

        /// Sometimes `builtin_instance_counter` JSON object is returned empty.
        #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
        #[serde(untagged)]
        #[serde(deny_unknown_fields)]
        pub enum BuiltinInstanceCounter {
            Normal(NormalBuiltinInstanceCounter),
            Empty(EmptyBuiltinInstanceCounter),
        }

        #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct NormalBuiltinInstanceCounter {
            bitwise_builtin: u64,
            ecdsa_builtin: u64,
            ec_op_builtin: u64,
            output_builtin: u64,
            pedersen_builtin: u64,
            range_check_builtin: u64,
        }

        #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
        pub struct EmptyBuiltinInstanceCounter {}
    }

    /// Represents deserialized L1 to L2 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct L1ToL2Message {
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub from_address: EthereumAddress,
        #[serde_as(as = "Vec<L1ToL2MessagePayloadElemAsDecimalStr>")]
        pub payload: Vec<L1ToL2MessagePayloadElem>,
        pub selector: EntryPoint,
        pub to_address: ContractAddress,
        #[serde(default)]
        pub nonce: Option<L1ToL2MessageNonce>,
    }

    /// Represents deserialized L2 to L1 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct L2ToL1Message {
        pub from_address: ContractAddress,
        #[serde_as(as = "Vec<L2ToL1MessagePayloadElemAsDecimalStr>")]
        pub payload: Vec<L2ToL1MessagePayloadElem>,
        #[serde_as(as = "EthereumAddressAsHexStr")]
        pub to_address: EthereumAddress,
    }

    /// Represents deserialized L2 transaction receipt data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        pub events: Vec<Event>,
        pub execution_resources: ExecutionResources,
        pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub transaction_hash: StarknetTransactionHash,
        pub transaction_index: StarknetTransactionIndex,
    }

    /// Represents deserialized L2 transaction event data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Event {
        #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
        data: Vec<EventData>,
        from_address: ContractAddress,
        #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
        keys: Vec<EventKey>,
    }

    /// Represents deserialized object containing L2 contract address and transaction type.
    #[serde_as]
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Source {
        pub contract_address: ContractAddress,
        pub r#type: Type,
    }

    /// Represents deserialized L2 transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Transaction {
        #[serde_as(as = "Option<Vec<CallParamAsDecimalStr>>")]
        #[serde(default)]
        pub calldata: Option<Vec<CallParam>>,
        #[serde_as(as = "Option<Vec<ConstructorParamAsDecimalStr>>")]
        #[serde(default)]
        pub constructor_calldata: Option<Vec<ConstructorParam>>,
        pub contract_address: ContractAddress,
        #[serde(default)]
        pub contract_address_salt: Option<ContractAddressSalt>,
        #[serde(default)]
        pub entry_point_type: Option<EntryPointType>,
        #[serde(default)]
        pub entry_point_selector: Option<EntryPoint>,
        #[serde_as(as = "Option<Vec<TransactionSignatureElemAsDecimalStr>>")]
        #[serde(default)]
        pub signature: Option<Vec<TransactionSignatureElem>>,
        pub transaction_hash: StarknetTransactionHash,
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

    /// Describes L2 transaction failure details.
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Failure {
        pub code: String,
        pub error_message: String,
        pub tx_id: u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code() {
        let abi = r#"[{"inputs": [{"name": "amount", "type": "felt"}], "name": "increase_balance", "outputs": [], "type": "function"}, {"inputs": [], "name": "get_balance", "outputs": [{"name": "res", "type": "felt"}], "stateMutability": "view", "type": "function"}]"#;
        let bytecode = vec![
            StarkHash::from_hex_str("0x123").unwrap(),
            StarkHash::from_hex_str("0x4567890").unwrap(),
        ];
        let encoded_bytecode = serde_json::to_string(&bytecode).unwrap();
        let encoded = format!("{{ \"abi\": {}, \"bytecode\": {} }}", abi, encoded_bytecode);

        let code = serde_json::from_str::<Code>(&encoded).unwrap();

        assert_eq!(code.bytecode, bytecode);
        assert_eq!(code.abi.get(), abi);
    }
}
