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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub block_hash: StarknetBlockHash,
    pub block_number: StarknetBlockNumber,
    /// Excluded in blocks prior to StarkNet 0.9
    #[serde_as(as = "Option<GasPriceAsHexStr>")]
    #[serde(default)]
    pub gas_price: Option<GasPrice>,
    pub parent_block_hash: StarknetBlockHash,
    /// Excluded in blocks prior to StarkNet 0.8
    #[serde(default)]
    pub sequencer_address: Option<SequencerAddress>,
    pub state_root: GlobalRoot,
    pub status: Status,
    pub timestamp: StarknetBlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
    /// Version metadata introduced in 0.9.1, older blocks will not have it.
    #[serde(default)]
    pub starknet_version: Option<String>,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct PendingBlock {
    #[serde_as(as = "GasPriceAsHexStr")]
    pub gas_price: GasPrice,
    #[serde(rename = "parent_block_hash")]
    pub parent_hash: StarknetBlockHash,
    pub sequencer_address: SequencerAddress,
    pub status: Status,
    pub timestamp: StarknetBlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
    /// Version metadata introduced in 0.9.1, older blocks will not have it.
    #[serde(default)]
    pub starknet_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MaybePendingBlock {
    Block(Block),
    Pending(PendingBlock),
}

#[cfg(test)]
impl From<Block> for MaybePendingBlock {
    fn from(block: Block) -> Self {
        MaybePendingBlock::Block(block)
    }
}

impl From<PendingBlock> for MaybePendingBlock {
    fn from(pending: PendingBlock) -> Self {
        MaybePendingBlock::Pending(pending)
    }
}

impl MaybePendingBlock {
    pub fn as_block(self) -> Option<Block> {
        match self {
            MaybePendingBlock::Block(block) => Some(block),
            MaybePendingBlock::Pending(_) => None,
        }
    }

    pub fn transactions(&self) -> &[transaction::Transaction] {
        match self {
            MaybePendingBlock::Block(b) => &b.transactions,
            MaybePendingBlock::Pending(p) => &p.transactions,
        }
    }

    pub fn receipts(&self) -> &[transaction::Receipt] {
        match self {
            MaybePendingBlock::Block(b) => &b.transaction_receipts,
            MaybePendingBlock::Pending(p) => &p.transaction_receipts,
        }
    }

    pub fn status(&self) -> Status {
        match self {
            MaybePendingBlock::Block(b) => b.status,
            MaybePendingBlock::Pending(p) => p.status,
        }
    }
}

/// Block and transaction status values.
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, serde::Serialize)]
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
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Problems {
        #[serde_as(as = "HashMap<_, _>")]
        pub calldata: HashMap<u64, Vec<String>>,
    }
}

/// Used to deserialize replies to [ClientApi::transaction](crate::sequencer::ClientApi::transaction).
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
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
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
    }

    /// Represents execution resources for L2 transaction.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(untagged)]
        #[serde(deny_unknown_fields)]
        pub enum BuiltinInstanceCounter {
            Normal(NormalBuiltinInstanceCounter),
            Empty(EmptyBuiltinInstanceCounter),
        }

        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        #[serde(deny_unknown_fields)]
        pub struct NormalBuiltinInstanceCounter {
            bitwise_builtin: u64,
            ecdsa_builtin: u64,
            ec_op_builtin: u64,
            output_builtin: u64,
            pedersen_builtin: u64,
            range_check_builtin: u64,
        }

        #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
        pub struct EmptyBuiltinInstanceCounter {}
    }

    /// Represents deserialized L1 to L2 message.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde_as(as = "Option<FeeAsHexStr>")]
        #[serde(default)]
        pub actual_fee: Option<Fee>,
        pub events: Vec<Event>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub execution_resources: Option<ExecutionResources>,
        pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub transaction_hash: StarknetTransactionHash,
        pub transaction_index: StarknetTransactionIndex,
    }

    /// Represents deserialized L2 transaction event data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Event {
        #[serde_as(as = "Vec<EventDataAsDecimalStr>")]
        pub data: Vec<EventData>,
        pub from_address: ContractAddress,
        #[serde_as(as = "Vec<EventKeyAsDecimalStr>")]
        pub keys: Vec<EventKey>,
    }

    /// Represents deserialized L2 transaction data.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "DEPLOY")]
        Deploy(DeployTransaction),
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeTransaction),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransaction),
    }

    impl Transaction {
        /// Returns hash of the transaction
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Transaction::Declare(t) => t.transaction_hash,
                Transaction::Deploy(t) => t.transaction_hash,
                Transaction::Invoke(t) => match t {
                    InvokeTransaction::V0(t) => t.transaction_hash,
                    InvokeTransaction::V1(t) => t.transaction_hash,
                },
                Transaction::L1Handler(t) => t.transaction_hash,
            }
        }
    }

    /// Represents deserialized L2 declare transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    /// Represents deserialized L2 deploy transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployTransaction {
        pub contract_address: ContractAddress,
        pub contract_address_salt: ContractAddressSalt,
        pub class_hash: ClassHash,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default)]
        pub version: TransactionVersion,
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(tag = "version")]
    pub enum InvokeTransaction {
        #[serde(rename = "0x0")]
        V0(InvokeTransactionV0),
        #[serde(rename = "0x1")]
        V1(InvokeTransactionV1),
    }

    impl<'de> Deserialize<'de> for InvokeTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;
            use web3::types::H256;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                #[serde(default)]
                pub version: TransactionVersion,
            }

            let mut v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            // remove "version", since v0 and v1 transactions use deny_unknown_fields
            v.as_object_mut().unwrap().remove("version");
            match version.version {
                TransactionVersion(x) if x == H256::from_low_u64_be(0) => Ok(Self::V0(
                    InvokeTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion(x) if x == H256::from_low_u64_be(1) => Ok(Self::V1(
                    InvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0 or 1")),
            }
        }
    }

    impl InvokeTransaction {
        pub fn signature(&self) -> &[TransactionSignatureElem] {
            match self {
                Self::V0(tx) => tx.signature.as_ref(),
                Self::V1(tx) => tx.signature.as_ref(),
            }
        }
    }

    /// Represents deserialized L2 invoke transaction v0 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV0 {
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
    }

    /// Represents deserialized L2 invoke transaction v1 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV1 {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub entry_point_type: EntryPointType,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub transaction_hash: StarknetTransactionHash,
    }

    /// Represents deserialized L2 declare transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L1HandlerTransaction {
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub nonce: TransactionNonce,
        pub calldata: Vec<CallParam>,
        pub transaction_hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    impl From<DeclareTransaction> for Transaction {
        fn from(tx: DeclareTransaction) -> Self {
            Self::Declare(tx)
        }
    }

    impl From<DeployTransaction> for Transaction {
        fn from(tx: DeployTransaction) -> Self {
            Self::Deploy(tx)
        }
    }

    impl From<InvokeTransaction> for Transaction {
        fn from(tx: InvokeTransaction) -> Self {
            Self::Invoke(tx)
        }
    }

    impl From<L1HandlerTransaction> for Transaction {
        fn from(tx: L1HandlerTransaction) -> Self {
            Self::L1Handler(tx)
        }
    }

    impl From<InvokeTransactionV0> for InvokeTransaction {
        fn from(tx: InvokeTransactionV0) -> Self {
            Self::V0(tx)
        }
    }

    impl From<InvokeTransactionV1> for InvokeTransaction {
        fn from(tx: InvokeTransactionV1) -> Self {
            Self::V1(tx)
        }
    }

    /// Describes L2 transaction failure details.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Failure {
        pub code: String,
        pub error_message: String,
        pub tx_id: u64,
    }
}

/// Used to deserialize a reply from
/// [ClientApi::state_update](crate::sequencer::ClientApi::state_update).
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
    use crate::core::{ClassHash, ContractAddress, ContractNonce, StorageAddress, StorageValue};
    use serde::Deserialize;
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// L2 state diff.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        #[serde_as(as = "HashMap<_, Vec<_>>")]
        pub storage_diffs: HashMap<ContractAddress, Vec<StorageDiff>>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub declared_contracts: Vec<ClassHash>,
        /// FIXME(0.10): drop the default once 0.10 hits mainnet
        #[serde(default)]
        pub nonces: HashMap<ContractAddress, ContractNonce>,
    }

    /// L2 storage diff.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        pub key: StorageAddress,
        pub value: StorageValue,
    }

    /// L2 contract data within state diff.
    #[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        pub address: ContractAddress,
        /// `class_hash` is the field name from cairo 0.9.0 onwards
        /// `contract_hash` is the name from cairo before 0.9.0
        #[serde(alias = "contract_hash")]
        pub class_hash: ClassHash,
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn contract_field_backward_compatibility() {
            use super::{ClassHash, ContractAddress, DeployedContract};
            use crate::starkhash;

            let expected = DeployedContract {
                address: ContractAddress::new_or_panic(starkhash!("01")),
                class_hash: ClassHash(starkhash!("02")),
            };

            // cario <0.9.0
            assert_eq!(
                serde_json::from_str::<DeployedContract>(
                    r#"{"address":"0x01","contract_hash":"0x02"}"#
                )
                .unwrap(),
                expected
            );
            // cario >=0.9.0
            assert_eq!(
                serde_json::from_str::<DeployedContract>(
                    r#"{"address":"0x01","class_hash":"0x02"}"#
                )
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
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: StarknetTransactionHash,
    }

    /// API response for a DECLARE transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: StarknetTransactionHash,
        pub class_hash: ClassHash,
    }

    /// API response for a DEPLOY transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: StarknetTransactionHash,
        pub address: ContractAddress,
    }

    #[cfg(test)]
    mod serde_test {
        use crate::starkhash;

        use super::*;

        #[test]
        fn test_invoke_response() {
            let result = serde_json::from_str::<InvokeResponse>(r#"{"code": "TRANSACTION_RECEIVED", "transaction_hash": "0x389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"}"#).unwrap();
            let expected = InvokeResponse {
                code: "TRANSACTION_RECEIVED".to_owned(),
                transaction_hash: StarknetTransactionHash(starkhash!(
                    "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
                )),
            };
            assert_eq!(expected, result);
        }

        #[test]
        fn test_deploy_response() {
            let result = serde_json::from_str::<DeployResponse>(r#"{"code": "TRANSACTION_RECEIVED", "transaction_hash": "0x296fb89b8a1c7487a1d4b27e1a1e33f440b05548e64980d06052bc089b1a51f", "address": "0x677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"}"#).unwrap();
            let expected = DeployResponse {
                code: "TRANSACTION_RECEIVED".to_owned(),
                transaction_hash: StarknetTransactionHash(starkhash!(
                    "0296fb89b8a1c7487a1d4b27e1a1e33f440b05548e64980d06052bc089b1a51f"
                )),
                address: ContractAddress::new_or_panic(starkhash!(
                    "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                )),
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

        use super::super::{StateUpdate, Transaction};

        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../fixtures/sequencer/", $file_name))
            };
        }

        #[test]
        fn block() {
            use super::super::MaybePendingBlock;

            serde_json::from_str::<MaybePendingBlock>(fixture!("0.8.2/block/genesis.json"))
                .unwrap();
            serde_json::from_str::<MaybePendingBlock>(fixture!("0.8.2/block/1716.json")).unwrap();
            serde_json::from_str::<MaybePendingBlock>(fixture!("0.8.2/block/pending.json"))
                .unwrap();
        }

        #[test]
        fn state_update() {
            // FIXME(0.10): update these fixtures once 0.10 is on mainnet

            // These fixtures do not contain nonces property (0.10 owards).
            serde_json::from_str::<StateUpdate>(fixture!("0.9.1/state_update/genesis.json"))
                .unwrap();
            serde_json::from_str::<StateUpdate>(fixture!("0.9.1/state_update/pending.json"))
                .unwrap();
            // This is from integration starknet_version 0.10 and contains the new nonces field.
            serde_json::from_str::<StateUpdate>(fixture!("integration/state_update/216572.json"))
                .unwrap();
        }

        #[test]
        fn transaction() {
            serde_json::from_str::<Transaction>(fixture!("0.8.2/txn/invoke.json")).unwrap();
        }
    }

    mod integration {
        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../fixtures/sequencer/integration/", $file_name))
            };
        }

        #[test]
        fn transactions() {
            use super::super::transaction::Transaction;

            serde_json::from_str::<Transaction>(r#"
            {
                "version": "0x1",
                "contract_address": "0x5fb7f82414f88e8418bb5f973bbc8fcb660a91913da262f47ecf8e898b83b09",
                "entry_point_selector": "0x15d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
                "entry_point_type": "EXTERNAL",
                "nonce": "0x0",
                "calldata": [
                    "0x1",
                    "0x6dec5ef1d559ba82f99e5a35cdad61bbc3c663d9f9bc3eda7660c0d2195c4f9",
                    "0x317eb442b72a9fae758d4fb26830ed0d9f31c8e7da4dbff4e8c59ea6a158e7f",
                    "0x0",
                    "0x4",
                    "0x4",
                    "0x208fe2128403ae7268d7198149eb050f000e185502807824aeafe0ba209a402",
                    "0x2",
                    "0x4f25c0268650df4a937463a47c1647c1661bc18e8c00eb935495edf635a70b4",
                    "0x219e05e77b5b719d7ea800f81e9b10d4b92ad8041dcfddbecb34c0b8e95a3a7"
                ],
                "signature": [
                    "0x26affc2bfec681bb5089e77b510efc937d4f4b6131c2a24440df8293cd44b08",
                    "0x7a04bda29e80b977d1a372ecdd1cf82f5b3381fad3e65006f0b0dfad7278fb1"
                ],
                "transaction_hash": "0x3c6b5dc87a4cc53a6a24bc25f79d298532ea17de1b2c912e5be5683b975b1a0",
                "max_fee": "0x2386f26fc10000",
                "type": "INVOKE_FUNCTION"
            }
            "#).unwrap();

            serde_json::from_str::<Transaction>(r#"
            {
                "version": "0x0",
                "contract_address": "0x73314940630fd6dcda0d772d4c972c4e0a9946bef9dabf4ef84eda8ef542b82",
                "entry_point_selector": "0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
                "nonce": "0x20",
                "calldata": [
                    "0xbe1259ff905cadbbaa62514388b71bdefb8aacc1",
                    "0x5fb7f82414f88e8418bb5f973bbc8fcb660a91913da262f47ecf8e898b83b09",
                    "0x4563918244f40000",
                    "0x0"
                ],
                "transaction_hash": "0x1b85068b298ffbb0ef33acc8952b7436c359883bd736b73e204c433a3eb9691",
                "type": "L1_HANDLER"
            }
            "#).unwrap();
        }

        #[test]
        fn block() {
            use super::super::MaybePendingBlock;

            serde_json::from_str::<MaybePendingBlock>(fixture!("block/pending.json")).unwrap();
            serde_json::from_str::<MaybePendingBlock>(fixture!("block/1.json")).unwrap();
            serde_json::from_str::<MaybePendingBlock>(fixture!("block/192844.json")).unwrap();
            serde_json::from_str::<MaybePendingBlock>(fixture!("block/216171.json")).unwrap();
            serde_json::from_str::<MaybePendingBlock>(fixture!("block/216591.json")).unwrap();
        }
    }
}
