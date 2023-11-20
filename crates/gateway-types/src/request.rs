//! Structures used for serializing requests to Starkware's sequencer REST API.
use pathfinder_common::{
    BlockHash, BlockNumber, CallParam, ContractAddress, Fee, TransactionSignatureElem,
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
    Hash(BlockHash),
    /// Special [`Tag`] describing a block
    Tag(Tag),
}

impl std::fmt::Display for BlockHashOrTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hash(BlockHash(h)) => f.write_str(&h.to_hex_str()),
            Self::Tag(t) => std::fmt::Display::fmt(t, f),
        }
    }
}

impl From<BlockHash> for BlockHashOrTag {
    fn from(hash: BlockHash) -> Self {
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
    Number(BlockNumber),
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

impl From<BlockNumber> for BlockNumberOrTag {
    fn from(number: BlockNumber) -> Self {
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
    use pathfinder_crypto::Felt;
    use serde_with::serde_as;
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

    #[serde_as]
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndOffset {
        pub selector: EntryPoint,
        #[serde_as(as = "OffsetSerde")]
        pub offset: ByteCodeOffset,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    #[serde(untagged)]
    pub enum OffsetSerde {
        HexStr(Felt),
        Decimal(u64),
    }

    impl serde_with::SerializeAs<ByteCodeOffset> for OffsetSerde {
        fn serialize_as<S>(source: &ByteCodeOffset, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            use serde::Serialize;

            Felt::serialize(&source.0, serializer)
        }
    }

    impl<'de> serde_with::DeserializeAs<'de, ByteCodeOffset> for OffsetSerde {
        fn deserialize_as<D>(deserializer: D) -> Result<ByteCodeOffset, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::Deserialize;

            let offset = OffsetSerde::deserialize(deserializer)?;
            let offset = match offset {
                OffsetSerde::HexStr(felt) => felt,
                OffsetSerde::Decimal(decimal) => Felt::from_u64(decimal),
            };
            Ok(ByteCodeOffset(offset))
        }
    }

    /// Descriptor of an entry point in a Sierra class.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    pub struct SelectorAndFunctionIndex {
        pub selector: EntryPoint,
        pub function_idx: u64,
    }
}

pub mod add_transaction {
    use super::contract::{EntryPointType, SelectorAndFunctionIndex, SelectorAndOffset};
    use super::{CallParam, ContractAddress, Fee, TransactionSignatureElem};
    use pathfinder_common::{
        CasmHash, ClassHash, ContractAddressSalt, EntryPoint, TransactionNonce, TransactionVersion,
    };
    use pathfinder_serde::{
        CallParamAsDecimalStr, TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
    };
    use serde_with::serde_as;
    use std::collections::HashMap;

    /// Both variants are somewhat different compared to the contract definition we're using
    /// for class hash calculation. The actual program contents are not relevant
    /// for us, and they are sent as a gzip + base64 encoded string via the API.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(untagged)]
    pub enum ContractDefinition {
        Cairo(CairoContractDefinition),
        Sierra(SierraContractDefinition),
    }

    /// Definition of a Cairo 0.x contract.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct CairoContractDefinition {
        // gzip + base64 encoded JSON of the compiled contract JSON
        pub program: String,
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndOffset>>,
        pub abi: Option<serde_json::Value>,
    }

    /// Definition of a Cairo 1.x contract.
    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    pub struct SierraContractDefinition {
        // gzip + base64 encoded JSON of the compiled contract JSON
        pub sierra_program: String,
        pub contract_class_version: String,
        pub entry_points_by_type: HashMap<EntryPointType, Vec<SelectorAndFunctionIndex>>,
        pub abi: String,
    }

    /// Account deployment transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct DeployAccount {
        // Transaction properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

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
        // Transaction properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // AccountTransaction properties
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        // NOTE: this is optional because Invoke v0 transactions do not have a nonce
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub nonce: Option<TransactionNonce>,

        pub sender_address: ContractAddress,
        // NOTE: this is optional because only Invoke v0 transactions have an entry point selector
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub entry_point_selector: Option<EntryPoint>,
        #[serde_as(as = "Vec<CallParamAsDecimalStr>")]
        pub calldata: Vec<CallParam>,
    }

    /// Declare transaction details.
    #[serde_as]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    pub struct Declare {
        // Transaction properties
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // AccountTransaction properties -- except for nonce which is non-optional here
        pub max_fee: Fee,
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,

        pub contract_class: ContractDefinition,
        pub sender_address: ContractAddress,
        pub nonce: TransactionNonce,

        // Required for declare v2 transactions
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub compiled_class_hash: Option<CasmHash>,
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
        #[serde(rename = "DECLARE")]
        Declare(Declare),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccount),
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use starknet_gateway_test_fixtures::add_transaction::INVOKE_CONTRACT_WITH_SIGNATURE;

        #[test]
        fn test_invoke_with_signature() {
            serde_json::from_str::<AddTransaction>(INVOKE_CONTRACT_WITH_SIGNATURE).unwrap();
        }

        mod byte_code_offset {
            use pathfinder_common::macro_prelude::*;
            use pathfinder_common::ByteCodeOffset;
            use pathfinder_crypto::Felt;

            use crate::request::contract::SelectorAndOffset;

            #[test]
            fn with_hex_offset() {
                let json = r#"{
                    "selector": "0x12345",
                    "offset": "0xabcdef"
                }"#;

                let result = serde_json::from_str::<SelectorAndOffset>(json).unwrap();

                let expected = SelectorAndOffset {
                    selector: entry_point!("0x12345"),
                    offset: byte_code_offset!("0xabcdef"),
                };

                assert_eq!(result, expected);
            }

            #[test]
            fn with_decimal_offset() {
                let json = r#"{
                    "selector": "0x12345",
                    "offset": 199128127
                }"#;

                let result = serde_json::from_str::<SelectorAndOffset>(json).unwrap();

                let expected = SelectorAndOffset {
                    selector: entry_point!("0x12345"),
                    offset: ByteCodeOffset(Felt::from_u64(199128127)),
                };

                assert_eq!(result, expected);
            }
        }
    }
}
