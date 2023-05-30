//! Structures used for deserializing replies from Starkware's sequencer REST API.
use pathfinder_common::{
    BlockHash, BlockNumber, BlockTimestamp, EthereumAddress, GasPrice, SequencerAddress,
    StarknetVersion, StateCommitment,
};
use pathfinder_serde::{EthereumAddressAsHexStr, GasPriceAsHexStr};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

/// Used to deserialize replies to Starknet block requests.
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub block_hash: BlockHash,
    pub block_number: BlockNumber,
    /// Excluded in blocks prior to Starknet 0.9
    #[serde_as(as = "Option<GasPriceAsHexStr>")]
    #[serde(default)]
    pub gas_price: Option<GasPrice>,
    pub parent_block_hash: BlockHash,
    /// Excluded in blocks prior to Starknet 0.8
    #[serde(default)]
    pub sequencer_address: Option<SequencerAddress>,
    // Historical blocks (pre v0.11) still use `state_root`.
    #[serde(alias = "state_root")]
    pub state_commitment: StateCommitment,
    pub status: Status,
    pub timestamp: BlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
    /// Version metadata introduced in 0.9.1, older blocks will not have it.
    #[serde(default)]
    pub starknet_version: StarknetVersion,
}

#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[cfg_attr(test, derive(serde::Serialize))]
pub struct PendingBlock {
    #[serde_as(as = "GasPriceAsHexStr")]
    pub gas_price: GasPrice,
    #[serde(rename = "parent_block_hash")]
    pub parent_hash: BlockHash,
    pub sequencer_address: SequencerAddress,
    pub status: Status,
    pub timestamp: BlockTimestamp,
    pub transaction_receipts: Vec<transaction::Receipt>,
    pub transactions: Vec<transaction::Transaction>,
    /// Version metadata introduced in 0.9.1, older blocks will not have it.
    #[serde(default)]
    pub starknet_version: StarknetVersion,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MaybePendingBlock {
    Block(Block),
    Pending(PendingBlock),
}

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

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::NotReceived => write!(f, "NOT_RECEIVED"),
            Status::Received => write!(f, "RECEIVED"),
            Status::Pending => write!(f, "PENDING"),
            Status::Rejected => write!(f, "REJECTED"),
            Status::AcceptedOnL1 => write!(f, "ACCEPTED_ON_L1"),
            Status::AcceptedOnL2 => write!(f, "ACCEPTED_ON_L2"),
            Status::Reverted => write!(f, "REVERTED"),
            Status::Aborted => write!(f, "ABORTED"),
        }
    }
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

/// Used to deserialize replies to Starknet transaction requests.
#[serde_as]
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    #[serde(default)]
    pub block_hash: Option<BlockHash>,
    #[serde(default)]
    pub block_number: Option<BlockNumber>,
    pub status: Status,
    #[serde(default)]
    pub transaction: Option<transaction::Transaction>,
    #[serde(default)]
    pub transaction_index: Option<u64>,
    #[serde(default)]
    pub transaction_failure_reason: Option<transaction::Failure>,
}

/// Used to deserialize replies to Starknet transaction status requests.
#[serde_as]
#[derive(Copy, Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransactionStatus {
    #[serde(default)]
    pub block_hash: Option<BlockHash>,
    pub tx_status: Status,
}

/// Types used when deserializing L2 transaction related data.
pub mod transaction {
    use pathfinder_common::{
        CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
        EntryPoint, EthereumAddress, EventData, EventKey, Fee, L1ToL2MessageNonce,
        L1ToL2MessagePayloadElem, L2ToL1MessagePayloadElem, TransactionHash, TransactionIndex,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, EthereumAddressAsHexStr,
        EventDataAsDecimalStr, EventKeyAsDecimalStr, L1ToL2MessagePayloadElemAsDecimalStr,
        L2ToL1MessagePayloadElemAsDecimalStr, TransactionSignatureElemAsDecimalStr,
        TransactionVersionAsHexStr,
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
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct Receipt {
        #[serde(default)]
        pub actual_fee: Option<Fee>,
        pub events: Vec<Event>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub execution_resources: Option<ExecutionResources>,
        pub l1_to_l2_consumed_message: Option<L1ToL2Message>,
        pub l2_to_l1_messages: Vec<L2ToL1Message>,
        pub transaction_hash: TransactionHash,
        pub transaction_index: TransactionIndex,
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
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(tag = "type")]
    #[serde(deny_unknown_fields)]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "DEPLOY")]
        // FIXME regenesis: remove Deploy txn type after regenesis
        // We are keeping this type of transaction until regenesis
        // only to support older pre-0.11.0 blocks
        Deploy(DeployTransaction),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccountTransaction),
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeTransaction),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransaction),
    }

    // This manual deserializtion is a work-around for L1 handler transactions
    // historically being served as Invoke V0. However, the gateway has retroactively
    // changed these to L1 handlers. This means older databases will have these as Invoke
    // but modern one's as L1 handler. This causes confusion, so we convert these old Invoke
    // to L1 handler manually.
    //
    // The alternative is to do a costly database migration which involves opening every tx.
    //
    // This work-around may be removed once we are certain all databases no longer contain these
    // transactions, which will likely only occur after either a migration, or regenesis.
    impl<'de> Deserialize<'de> for Transaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            /// Copy of [Transaction] to deserialize into, before converting to [Transaction]
            /// with the potential Invoke V0 -> L1 handler cast.
            #[derive(Deserialize)]
            #[serde(tag = "type", deny_unknown_fields)]
            pub enum InnerTransaction {
                #[serde(rename = "DECLARE")]
                Declare(DeclareTransaction),
                #[serde(rename = "DEPLOY")]
                Deploy(DeployTransaction),
                #[serde(rename = "DEPLOY_ACCOUNT")]
                DeployAccount(DeployAccountTransaction),
                #[serde(rename = "INVOKE_FUNCTION")]
                Invoke(InvokeTransaction),
                #[serde(rename = "L1_HANDLER")]
                L1Handler(L1HandlerTransaction),
            }

            let tx = InnerTransaction::deserialize(deserializer)?;
            let tx = match tx {
                InnerTransaction::Declare(x) => Transaction::Declare(x),
                InnerTransaction::Deploy(x) => Transaction::Deploy(x),
                InnerTransaction::DeployAccount(x) => Transaction::DeployAccount(x),
                InnerTransaction::Invoke(InvokeTransaction::V0(i))
                    if i.entry_point_type == Some(EntryPointType::L1Handler) =>
                {
                    let l1_handler = L1HandlerTransaction {
                        contract_address: i.sender_address,
                        entry_point_selector: i.entry_point_selector,
                        nonce: TransactionNonce::ZERO,
                        calldata: i.calldata,
                        transaction_hash: i.transaction_hash,
                        version: TransactionVersion::ZERO,
                    };

                    Transaction::L1Handler(l1_handler)
                }
                InnerTransaction::Invoke(x) => Transaction::Invoke(x),
                InnerTransaction::L1Handler(x) => Transaction::L1Handler(x),
            };

            Ok(tx)
        }
    }

    impl Transaction {
        /// Returns hash of the transaction
        pub fn hash(&self) -> TransactionHash {
            match self {
                Transaction::Declare(t) => match t {
                    DeclareTransaction::V0(t) => t.transaction_hash,
                    DeclareTransaction::V1(t) => t.transaction_hash,
                    DeclareTransaction::V2(t) => t.transaction_hash,
                },
                Transaction::Deploy(t) => t.transaction_hash,
                Transaction::DeployAccount(t) => t.transaction_hash,
                Transaction::Invoke(t) => match t {
                    InvokeTransaction::V0(t) => t.transaction_hash,
                    InvokeTransaction::V1(t) => t.transaction_hash,
                },
                Transaction::L1Handler(t) => t.transaction_hash,
            }
        }

        pub fn contract_address(&self) -> ContractAddress {
            match self {
                Transaction::Declare(DeclareTransaction::V0(t)) => t.sender_address,
                Transaction::Declare(DeclareTransaction::V1(t)) => t.sender_address,
                Transaction::Declare(DeclareTransaction::V2(t)) => t.sender_address,
                Transaction::Deploy(t) => t.contract_address,
                Transaction::DeployAccount(t) => t.contract_address,
                Transaction::Invoke(t) => match t {
                    InvokeTransaction::V0(t) => t.sender_address,
                    InvokeTransaction::V1(t) => t.sender_address,
                },
                Transaction::L1Handler(t) => t.contract_address,
            }
        }
    }

    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[serde(tag = "version")]
    pub enum DeclareTransaction {
        #[serde(rename = "0x0")]
        V0(DeclareTransactionV0V1),
        #[serde(rename = "0x1")]
        V1(DeclareTransactionV0V1),
        #[serde(rename = "0x2")]
        V2(DeclareTransactionV2),
    }

    impl<'de> Deserialize<'de> for DeclareTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use primitive_types::H256;
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                #[serde(default = "transaction_version_zero")]
                pub version: TransactionVersion,
            }

            let mut v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            // remove "version", since v0 and v1 transactions use deny_unknown_fields
            v.as_object_mut()
                .expect("must be an object because deserializing version succeeded")
                .remove("version");
            match version.version {
                TransactionVersion(x) if x == H256::from_low_u64_be(0) => Ok(Self::V0(
                    DeclareTransactionV0V1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion(x) if x == H256::from_low_u64_be(1) => Ok(Self::V1(
                    DeclareTransactionV0V1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion(x) if x == H256::from_low_u64_be(2) => Ok(Self::V2(
                    DeclareTransactionV2::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0, 1 or 2")),
            }
        }
    }

    impl DeclareTransaction {
        pub fn signature(&self) -> &[TransactionSignatureElem] {
            match self {
                DeclareTransaction::V0(tx) => tx.signature.as_ref(),
                DeclareTransaction::V1(tx) => tx.signature.as_ref(),
                DeclareTransaction::V2(tx) => tx.signature.as_ref(),
            }
        }
    }

    /// A version 0 or 1 declare transaction.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV0V1 {
        pub class_hash: ClassHash,
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
    }

    /// A version 2 declare transaction.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareTransactionV2 {
        pub class_hash: ClassHash,
        pub max_fee: Fee,
        pub nonce: TransactionNonce,
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        #[serde(default)]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
        pub compiled_class_hash: CasmHash,
    }

    fn transaction_version_zero() -> TransactionVersion {
        TransactionVersion(primitive_types::H256::zero())
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
        pub transaction_hash: TransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default = "transaction_version_zero")]
        pub version: TransactionVersion,
    }

    /// Represents deserialized L2 deploy account transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployAccountTransaction {
        pub contract_address: ContractAddress,
        pub transaction_hash: TransactionHash,
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub contract_address_salt: ContractAddressSalt,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
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
            use primitive_types::H256;
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                #[serde(default = "transaction_version_zero")]
                pub version: TransactionVersion,
            }

            let mut v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            // remove "version", since v0 and v1 transactions use deny_unknown_fields
            v.as_object_mut()
                .expect("must be an object because deserializing version succeeded")
                .remove("version");
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
        // contract_address is the historic name for this field. sender_address was
        // introduced with starknet v0.11. Although the gateway no longer uses the historic
        // name at all, this alias must be kept until a database migration fixes all historic
        // transaction naming, or until regenesis removes them all.
        #[serde(alias = "contract_address")]
        pub sender_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub entry_point_type: Option<EntryPointType>,
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub transaction_hash: TransactionHash,
    }

    /// Represents deserialized L2 invoke transaction v1 data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeTransactionV1 {
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
        // contract_address is the historic name for this field. sender_address was
        // introduced with starknet v0.11. Although the gateway no longer uses the historic
        // name at all, this alias must be kept until a database migration fixes all historic
        // transaction naming, or until regenesis removes them all.
        #[serde(alias = "contract_address")]
        pub sender_address: ContractAddress,
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
        pub transaction_hash: TransactionHash,
    }

    /// Represents deserialized L2 "L1 handler" transaction data.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct L1HandlerTransaction {
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        // FIXME: remove once starkware fixes their gateway bug which was missing this field.
        #[serde(default = "l1_handler_default_nonce")]
        pub nonce: TransactionNonce,
        pub calldata: Vec<CallParam>,
        pub transaction_hash: TransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
    }

    const fn l1_handler_default_nonce() -> TransactionNonce {
        TransactionNonce(stark_hash::Felt::ZERO)
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
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum MaybePendingStateUpdate {
    /// Always has a `block_hash` and a `new_root`
    StateUpdate(StateUpdate),
    /// Does not contain `block_hash` and `new_root`
    Pending(PendingStateUpdate),
}

/// Used to deserialize replies to StarkNet state update requests except for the pending one.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateUpdate {
    pub block_hash: BlockHash,
    pub new_root: StateCommitment,
    pub old_root: StateCommitment,
    pub state_diff: state_update::StateDiff,
}

/// Used to deserialize replies to Starknet pending state update requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingStateUpdate {
    pub old_root: StateCommitment,
    pub state_diff: state_update::StateDiff,
}

// FIXME: move to a simple derive once mainnet moves to 0.11.0 and we don't have to care for new_root anymore
impl<'de> Deserialize<'de> for PendingStateUpdate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct BackwardCompatiblePendingStateUpdate {
            /// Unused but present for backwards compatibility as long as mainnet remains on 0.10.3
            #[serde(default, rename = "new_root")]
            pub _unused: Option<StateCommitment>,
            pub old_root: StateCommitment,
            pub state_diff: state_update::StateDiff,
        }

        let psu = BackwardCompatiblePendingStateUpdate::deserialize(deserializer)?;
        Ok(PendingStateUpdate {
            old_root: psu.old_root,
            state_diff: psu.state_diff,
        })
    }
}

/// Types used when deserializing state update related data.
pub mod state_update {
    use pathfinder_common::{
        CasmHash, ClassHash, ContractAddress, ContractNonce, SierraHash, StorageAddress,
        StorageValue,
    };
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// L2 state diff.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct StateDiff {
        #[serde_as(as = "HashMap<_, Vec<_>>")]
        pub storage_diffs: HashMap<ContractAddress, Vec<StorageDiff>>,
        pub deployed_contracts: Vec<DeployedContract>,
        pub old_declared_contracts: Vec<ClassHash>,
        pub declared_classes: Vec<DeclaredSierraClass>,
        pub nonces: HashMap<ContractAddress, ContractNonce>,
        pub replaced_classes: Vec<ReplacedClass>,
    }

    /// L2 storage diff.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct StorageDiff {
        pub key: StorageAddress,
        pub value: StorageValue,
    }

    /// L2 contract data within state diff.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct DeployedContract {
        pub address: ContractAddress,
        /// `class_hash` is the field name from cairo 0.9.0 onwards
        /// `contract_hash` is the name from cairo before 0.9.0
        #[serde(alias = "contract_hash")]
        pub class_hash: ClassHash,
    }

    /// Describes a newly declared class. Maps Sierra class hash to a Casm hash.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct DeclaredSierraClass {
        pub class_hash: SierraHash,
        pub compiled_class_hash: CasmHash,
    }

    /// Describes a newly replaced class. Maps contract address to a new class.
    #[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
    #[serde(deny_unknown_fields)]
    pub struct ReplacedClass {
        pub address: ContractAddress,
        pub class_hash: ClassHash,
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn contract_field_backward_compatibility() {
            use super::{ClassHash, ContractAddress, DeployedContract};
            use pathfinder_common::felt;

            let expected = DeployedContract {
                address: ContractAddress::new_or_panic(felt!("0x1")),
                class_hash: ClassHash(felt!("0x2")),
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

/// Used to deserialize replies to Starknet Ethereum contract requests.
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
    use pathfinder_common::{ClassHash, ContractAddress, TransactionHash};

    /// API response for an INVOKE_FUNCTION transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct InvokeResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: TransactionHash,
    }

    /// API response for a DECLARE transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeclareResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: TransactionHash,
        pub class_hash: ClassHash,
    }

    /// API response for a DEPLOY transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: TransactionHash,
        pub address: ContractAddress,
    }

    /// API response for a DEPLOY ACCOUNT transaction
    #[derive(Clone, Debug, serde::Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    pub struct DeployAccountResponse {
        pub code: String, // TRANSACTION_RECEIVED
        pub transaction_hash: TransactionHash,
        pub address: ContractAddress,
    }

    #[cfg(test)]
    mod serde_test {
        use super::*;
        use pathfinder_common::felt;

        #[test]
        fn test_invoke_response() {
            let result = serde_json::from_str::<InvokeResponse>(r#"{"code": "TRANSACTION_RECEIVED", "transaction_hash": "0x389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"}"#).unwrap();
            let expected = InvokeResponse {
                code: "TRANSACTION_RECEIVED".to_owned(),
                transaction_hash: TransactionHash(felt!(
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
                transaction_hash: TransactionHash(felt!(
                    "0296fb89b8a1c7487a1d4b27e1a1e33f440b05548e64980d06052bc089b1a51f"
                )),
                address: ContractAddress::new_or_panic(felt!(
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
        use super::super::{MaybePendingStateUpdate, Transaction};
        use starknet_gateway_test_fixtures::*;

        #[test]
        fn block() {
            use super::super::MaybePendingBlock;

            // Mainnet block 192 contains an L1_HANDLER transaction without a nonce.
            serde_json::from_str::<MaybePendingBlock>(old::block::NUMBER_192).unwrap();
            serde_json::from_str::<MaybePendingBlock>(v0_8_2::block::GENESIS).unwrap();
            serde_json::from_str::<MaybePendingBlock>(v0_8_2::block::NUMBER_1716).unwrap();
            serde_json::from_str::<MaybePendingBlock>(v0_8_2::block::PENDING).unwrap();
            // This is from integration starknet_version 0.10 and contains the new version 1 invoke transaction.
            serde_json::from_str::<MaybePendingBlock>(integration::block::NUMBER_216591).unwrap();
            // This is from integration starknet_version 0.10.0 and contains the new L1 handler transaction.
            serde_json::from_str::<MaybePendingBlock>(integration::block::NUMBER_216171).unwrap();
            // This is from integration starknet_version 0.10.1 and contains the new deploy account transaction.
            serde_json::from_str::<MaybePendingBlock>(integration::block::NUMBER_228457).unwrap();
        }

        #[test]
        fn state_update() {
            // This is from integration starknet_version 0.11 and contains the new declared_classes field.
            serde_json::from_str::<MaybePendingStateUpdate>(
                integration::state_update::NUMBER_283364,
            )
            .unwrap();
            // This is from integration starknet_version 0.11 and contains the new replaced_classes field.
            serde_json::from_str::<MaybePendingStateUpdate>(
                integration::state_update::NUMBER_283428,
            )
            .unwrap();
        }

        #[test]
        fn transaction() {
            serde_json::from_str::<Transaction>(v0_8_2::transaction::INVOKE).unwrap();
        }

        #[test]
        fn legacy_l1_handler_is_invoke() {
            // In the times before L1 Handler became an official tx variant,
            // these were instead served as Invoke V0 txs. This test ensures
            // that we correctly map these historic txs to L1 Handler.
            use super::super::transaction::Transaction as TransactionVariant;

            let json = serde_json::json!({
                "type":"INVOKE_FUNCTION",
                "calldata":[
                    "580042449035822898911647251144793933582335302582",
                    "3241583063705060367416058138609427972824194056099997457116843686898315086623",
                    "2000000000000000000",
                    "0",
                    "725188533692944996190142472767755401716439215485"
                ],
                "contract_address":"0x1108cdbe5d82737b9057590adaf97d34e74b5452f0628161d237746b6fe69e",
                "entry_point_selector":"0x2d757788a8d8d6f21d1cd40bce38a8222d70654214e96ff95d8086e684fbee5",
                "entry_point_type":"L1_HANDLER",
                "max_fee":"0x0",
                "signature":[],
                "transaction_hash":"0x70cad5b0d09ff2b252d3bf040708a89e6f175715f5f550e8d8161fabef01261"
            });

            let tx: TransactionVariant = serde_json::from_value(json).unwrap();

            assert_matches::assert_matches!(tx, TransactionVariant::L1Handler(_));
        }
    }
}
