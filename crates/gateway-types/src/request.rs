//! Structures used for serializing requests to Starkware's sequencer REST API.
use pathfinder_common::{
    CallParam, ContractAddress, EntryPoint, Fee, StarknetBlockHash, StarknetBlockNumber,
    TransactionSignatureElem,
};
use serde::{Deserialize, Serialize};

/// Special tag used when specifying the `latest` or `pending` block.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum Tag {
    /// The most recent fully constructed block
    ///
    /// Represented as the JSON string `"latest"` when passed as an RPC method argument,
    /// for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxsByHash","params":["latest"]}`
    #[serde(rename = "latest")]
    Latest,
    /// Currently constructed block
    ///
    /// Represented as the JSON string `"pending"` when passed as an RPC method argument,
    /// for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxsByHash","params":["pending"]}`
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
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockHashOrTag {
    /// Hash of a block
    ///
    /// Represented as a `0x`-prefixed hex JSON string of length from 1 up to 64 characters
    /// when passed as an RPC method argument, for example:
    /// `{"jsonrpc":"2.0","id":"0","method":"starknet_getBlockWithTxsByHash","params":["0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b"]}`
    Hash(StarknetBlockHash),
    /// Special [`Tag`] describing a block
    Tag(Tag),
}

impl std::fmt::Display for BlockHashOrTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hash(StarknetBlockHash(h)) => f.write_str(&h.to_hex_str()),
            Self::Tag(t) => std::fmt::Display::fmt(t, f),
        }
    }
}

impl From<StarknetBlockHash> for BlockHashOrTag {
    fn from(hash: StarknetBlockHash) -> Self {
        Self::Hash(hash)
    }
}

impl From<BlockHashOrTag> for pathfinder_common::BlockId {
    fn from(x: BlockHashOrTag) -> Self {
        match x {
            BlockHashOrTag::Hash(h) => Self::Hash(h),
            BlockHashOrTag::Tag(Tag::Latest) => Self::Latest,
            BlockHashOrTag::Tag(Tag::Pending) => Self::Pending,
        }
    }
}

/// A wrapper that contains either a block [Number](self::BlockNumberOrTag::Number) or a [Tag](self::BlockNumberOrTag::Tag).
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
#[serde(deny_unknown_fields)]
pub enum BlockNumberOrTag {
    /// Number (height) of a block
    Number(StarknetBlockNumber),
    /// Special [`Tag`] describing a block
    Tag(Tag),
}

impl std::fmt::Display for BlockNumberOrTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Number(n) => std::fmt::Display::fmt(n, f),
            Self::Tag(t) => std::fmt::Display::fmt(t, f),
        }
    }
}

impl From<StarknetBlockNumber> for BlockNumberOrTag {
    fn from(number: StarknetBlockNumber) -> Self {
        Self::Number(number)
    }
}

impl From<BlockNumberOrTag> for pathfinder_common::BlockId {
    fn from(x: BlockNumberOrTag) -> Self {
        match x {
            BlockNumberOrTag::Number(n) => Self::Number(n),
            BlockNumberOrTag::Tag(Tag::Latest) => Self::Latest,
            BlockNumberOrTag::Tag(Tag::Pending) => Self::Pending,
        }
    }
}

pub mod contract {
    use pathfinder_common::{ByteCodeOffset, EntryPoint};
    use std::fmt;

    #[derive(Copy, Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Hash, Eq)]
    #[serde(deny_unknown_fields)]
    pub enum EntryPointType {
        #[serde(rename = "EXTERNAL")]
        External,
        #[serde(rename = "L1_HANDLER")]
        L1Handler,
        #[serde(rename = "CONSTRUCTOR")]
        Constructor,
    }

    impl fmt::Display for EntryPointType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use EntryPointType::*;
            f.pad(match self {
                External => "EXTERNAL",
                L1Handler => "L1_HANDLER",
                Constructor => "CONSTRUCTOR",
            })
        }
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndOffset {
        pub selector: EntryPoint,
        pub offset: ByteCodeOffset,
    }
}

pub mod add_transaction {
    use super::contract::{EntryPointType, SelectorAndOffset};
    use super::{CallParam, ContractAddress, EntryPoint, Fee, TransactionSignatureElem};
    use pathfinder_common::{
        ClassHash, ConstructorParam, ContractAddressSalt, TransactionNonce, TransactionVersion,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, ConstructorParamAsDecimalStr, FeeAsHexStr,
        TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
    };
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// Definition of a contract.
    ///
    /// This is somewhat different compared to the contract definition we're using
    /// for class hash calculation. The actual program contents are not relevant
    /// for us, and they are sent as a gzip + base64 encoded string via the API.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct ContractDefinition {
        // gzip + base64 encoded JSON of the compiled contract JSON
        pub program: String,
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>>,
        pub abi: Option<serde_json::Value>,
    }

    /// Contract deployment transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct Deploy {
        // Transacion properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        pub contract_address_salt: ContractAddressSalt,
        pub contract_definition: ContractDefinition,
        #[serde_as(as = "Vec<ConstructorParamAsDecimalStr>")]
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    /// Account deployment transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct DeployAccount {
        // Transaction properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub class_hash: ClassHash,
        pub contract_address_salt: ContractAddressSalt,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub constructor_calldata: Vec<CallParam>,
    }

    /// Invoke contract transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct InvokeFunction {
        // Transacion properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // AccountTransaction properties
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: Option<TransactionNonce>,

        pub contract_address: ContractAddress,
        pub entry_point_selector: Option<EntryPoint>,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
    }

    /// Declare transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct Declare {
        // Transacion properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // AccountTransaction properties -- except for nonce which is non-optional here
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,

        pub contract_class: ContractDefinition,
        pub sender_address: ContractAddress,
        pub nonce: TransactionNonce,
    }

    /// Add transaction API operation.
    ///
    /// This adds the "type" attribute to the JSON request according the type of
    /// the transaction (invoke or deploy).
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(tag = "type")]
    pub enum AddTransaction {
        #[serde(rename = "INVOKE_FUNCTION")]
        Invoke(InvokeFunction),
        #[serde(rename = "DEPLOY")]
        Deploy(Deploy),
        #[serde(rename = "DECLARE")]
        Declare(Declare),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccount),
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use starknet_gateway_test_fixtures::add_transaction::{
            DEPLOY_OPENZEPPELIN_ACCOUNT, DEPLOY_TRANSACTION, INVOKE_CONTRACT_WITH_SIGNATURE,
        };

        #[test]
        fn test_deploy() {
            serde_json::from_str::<AddTransaction>(DEPLOY_TRANSACTION).unwrap();
        }

        #[test]
        fn test_deploy_openzeppelin_account() {
            serde_json::from_str::<AddTransaction>(DEPLOY_OPENZEPPELIN_ACCOUNT).unwrap();
        }

        #[test]
        fn test_invoke_with_signature() {
            serde_json::from_str::<AddTransaction>(INVOKE_CONTRACT_WITH_SIGNATURE).unwrap();
        }
    }
}
