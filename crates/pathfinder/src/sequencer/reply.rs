//! Structures used for deserializing replies from Starkware's sequencer REST API.
use crate::{
    core::{
        CallResultValue, EthereumAddress, GasPrice, GlobalRoot, SequencerAddress,
        StarknetBlockHash, StarknetBlockNumber, StarknetBlockTimestamp,
    },
    rpc::serde::{EthereumAddressAsHexStr, GasPriceAsHexStr},
};
use serde::Deserialize;
use serde_with::serde_as;

/// Used to deserialize replies to [ClientApi::block](crate::sequencer::ClientApi::block).
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    #[serde(default)]
    pub block_hash: Option<StarknetBlockHash>,
    #[serde(default)]
    pub block_number: Option<StarknetBlockNumber>,
    #[serde_as(as = "Option<GasPriceAsHexStr>")]
    #[serde(default)]
    pub gas_price: Option<GasPrice>,
    pub parent_block_hash: StarknetBlockHash,
    #[serde(default)]
    pub sequencer_address: Option<SequencerAddress>,
    #[serde(default)]
    pub state_root: Option<GlobalRoot>,
    pub status: Status,
    pub timestamp: StarknetBlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
}

/// Block and transaction status values.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, serde::Serialize)]
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

/// Used to deserialize a reply from [ClientApi::call](crate::sequencer::ClientApi::call).
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

/// Used to deserialize replies to [ClientApi::transaction](crate::sequencer::ClientApi::transaction).
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

/// Used to deserialize replies to [ClientApi::transaction_status](crate::sequencer::ClientApi::transaction_status).
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
            CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
            EntryPoint, EthereumAddress, EventData, EventKey, Fee, L1ToL2MessageNonce,
            L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem, StarknetTransactionHash,
            StarknetTransactionIndex, TransactionNonce, TransactionSignatureElem,
            TransactionVersion,
        },
        rpc::serde::{
            CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
            EventDataAsDecimalStr, EventKeyAsDecimalStr, FeeAsHexStr,
            L1ToL2MessagePayloadElemAsDecimalStr, L2ToL1MessagePayloadElemAsDecimalStr,
            TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
        },
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;

    /// Represents deserialized L2 transaction entry point values.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct ExecutionResources {
        pub builtin_instance_counter: execution_resources::BuiltinInstanceCounter,
        pub n_steps: u64,
        pub n_memory_holes: u64,
    }

    /// Types used when deserializing L2 execution resources related data.
    pub mod execution_resources {
        use serde::{Deserialize, Serialize};

        /// Sometimes `builtin_instance_counter` JSON object is returned empty.
        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(untagged)]
        #[serde(deny_unknown_fields)]
        pub enum BuiltinInstanceCounter {
            Normal(NormalBuiltinInstanceCounter),
            Empty(EmptyBuiltinInstanceCounter),
        }

        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        pub struct NormalBuiltinInstanceCounter {
            bitwise_builtin: u64,
            ecdsa_builtin: u64,
            ec_op_builtin: u64,
            output_builtin: u64,
            pedersen_builtin: u64,
            range_check_builtin: u64,
        }

        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
        pub struct EmptyBuiltinInstanceCounter {}
    }

    /// Represents deserialized L1 to L2 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde_as(as = "Option<FeeAsHexStr>")]
        #[serde(default)]
        pub actual_fee: Option<Fee>,
        pub events: Vec<Event>,
        pub execution_resources: ExecutionResources,
        pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub transaction_hash: StarknetTransactionHash,
        pub transaction_index: StarknetTransactionIndex,
    }

    /// Represents deserialized L2 transaction event data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct Event {
        #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
        pub data: Vec<EventData>,
        pub from_address: ContractAddress,
        #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
        pub keys: Vec<EventKey>,
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(untagged)]
    #[serde(deny_unknown_fields)]
    pub enum Transaction {
        Declare(DeclareTransaction),
        Deploy(DeployTransaction),
        Invoke(InvokeTransaction),
    }

    impl Transaction {
        /// Returns hash of the transaction
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Transaction::Declare(t) => t.transaction_hash,
                Transaction::Deploy(t) => t.transaction_hash,
                Transaction::Invoke(t) => t.transaction_hash,
            }
        }
    }

    /// Represents deserialized L2 declare transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransaction {
        pub class_hash: ClassHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: StarknetTransactionHash,
        pub r#type: Type,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    /// Represents deserialized L2 deploy transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransaction {
        pub contract_address: ContractAddress,
        pub contract_address_salt: ContractAddressSalt,
        pub class_hash: ClassHash,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
        pub transaction_hash: StarknetTransactionHash,
        pub r#type: Type,
    }

    /// Represents deserialized L2 invoke transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransaction {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub entry_point_type: EntryPointType,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: StarknetTransactionHash,
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
        #[serde(rename = "DECLARE")]
        Declare,
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

/// Used to deserialize a reply from
/// [ClientApi::state_update](crate::sequencer::ClientApi::state_update).
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StateUpdate {
    /// This field is absent for a `pending` state update
    pub block_hash: Option<StarknetBlockHash>,
    pub new_root: GlobalRoot,
    pub old_root: GlobalRoot,
    pub state_diff: state_update::StateDiff,
}

/// Types used when deserializing state update related data.
pub mod state_update {
    use crate::core::{ClassHash, ContractAddress, StorageAddress, StorageValue};
    use serde::Deserialize;
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// L2 state diff.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        #[serde_as(as = "HashMap<_, Vec<_>>")]
        pub storage_diffs: HashMap<ContractAddress, Vec<StorageDiff>>,
        pub deployed_contracts: Vec<Contract>,
    }

    /// L2 storage diff.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        pub key: StorageAddress,
        pub value: StorageValue,
    }

    /// L2 contract data within state diff.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct Contract {
        pub address: ContractAddress,
        /// `class_hash` is the field name from cairo 0.9.0 onwards
        /// `contract_hash` is the name for cairo before 0.9.0
        #[serde(alias = "class_hash")]
        pub contract_hash: ClassHash,
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn contract_field_backward_compatibility() {
            use super::{ClassHash, Contract, ContractAddress};
            use stark_hash::StarkHash;

            let expected = Contract {
                address: ContractAddress(StarkHash::from_hex_str("0x01").unwrap()),
                contract_hash: ClassHash(StarkHash::from_hex_str("0x02").unwrap()),
            };

            // cario <0.9.0
            assert_eq!(
                serde_json::from_str::<Contract>(r#"{"address":"0x01","contract_hash":"0x02"}"#)
                    .unwrap(),
                expected
            );
            // cario >=0.9.0
            assert_eq!(
                serde_json::from_str::<Contract>(r#"{"address":"0x01","class_hash":"0x02"}"#)
                    .unwrap(),
                expected
            );
        }
    }
}

/// Used to deserialize a reply from [ClientApi::eth_contract_addresses](crate::sequencer::ClientApi::eth_contract_addresses).
#[serde_as]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthContractAddresses {
    #[serde(rename = "Starknet")]
    #[serde_as(as = "EthereumAddressAsHexStr")]
    pub starknet: EthereumAddress,
    #[serde_as(as = "EthereumAddressAsHexStr")]
    #[serde(rename = "GpsStatementVerifier")]
    pub gps_statement_verifier: EthereumAddress,
}

pub mod add_transaction {
    use crate::core::{ClassHash, ContractAddress, StarknetTransactionHash};

    /// API response for an INVOKE_FUNCTION transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: StarknetTransactionHash,
    }

    /// API response for a DECLARE transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: StarknetTransactionHash,
        pub class_hash: ClassHash,
    }

    /// API response for a DEPLOY transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: StarknetTransactionHash,
        pub address: ContractAddress,
    }

    #[cfg(test)]
    mod serde_test {
        use stark_hash::StarkHash;

        use super::*;

        #[test]
        fn test_invoke_response() {
            let result = serde_json::from_str::<InvokeResponse>(r#"{"code": "TRANSACTION_RECEIVED", "transaction_hash": "0x389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"}"#).unwrap();
            let expected = InvokeResponse {
                code: "TRANSACTION_RECEIVED".to_owned(),
                transaction_hash: StarknetTransactionHash(
                    StarkHash::from_hex_str(
                        "0x389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b",
                    )
                    .unwrap(),
                ),
            };
            assert_eq!(expected, result);
        }

        #[test]
        fn test_deploy_response() {
            let result = serde_json::from_str::<DeployResponse>(r#"{"code": "TRANSACTION_RECEIVED", "transaction_hash": "0x296fb89b8a1c7487a1d4b27e1a1e33f440b05548e64980d06052bc089b1a51f", "address": "0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"}"#).unwrap();
            let expected = DeployResponse {
                code: "TRANSACTION_RECEIVED".to_owned(),
                transaction_hash: StarknetTransactionHash(
                    StarkHash::from_hex_str(
                        "0x296fb89b8a1c7487a1d4b27e1a1e33f440b05548e64980d06052bc089b1a51f",
                    )
                    .unwrap(),
                ),
                address: ContractAddress(
                    StarkHash::from_hex_str(
                        "0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1",
                    )
                    .unwrap(),
                ),
            };
            assert_eq!(expected, result);
        }
    }
}

#[cfg(test)]
mod tests {
    /// The aim of these tests is to make sure pathfinder is still able to correctly
    /// deserialize replies from the mainnet sequencer when it still is using some
    /// previous version of cairo while at the same time the goerli sequencer is
    /// already using a newer version.
    mod backward_compatibility {

        use super::super::{Block, StateUpdate, Transaction};

        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../fixtures/sequencer/", $file_name))
            };
        }

        #[test]
        fn block() {
            serde_json::from_str::<Block>(fixture!("0.8.2/block/genesis.json")).unwrap();
            serde_json::from_str::<Block>(fixture!("0.8.2/block/1716.json")).unwrap();
            serde_json::from_str::<Block>(fixture!("0.8.2/block/pending.json")).unwrap();
        }

        #[test]
        fn state_update() {
            serde_json::from_str::<StateUpdate>(fixture!("0.8.2/state_update/genesis.json"))
                .unwrap();
            serde_json::from_str::<StateUpdate>(fixture!("0.8.2/state_update/pending.json"))
                .unwrap();
        }

        #[test]
        fn transaction() {
            serde_json::from_str::<Transaction>(fixture!("0.8.2/txn/invoke.json")).unwrap();
        }
    }
}
