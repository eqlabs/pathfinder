//! Common data structures used by the JSON-RPC API methods.

pub(crate) mod class;
pub use class::*;
pub mod syncing;

/// Groups all strictly input types of the RPC API.
pub mod request {
    use pathfinder_common::{
        CallParam, CasmHash, ClassHash, ContractAddress, ContractAddressSalt, EntryPoint, Fee,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_serde::{
        FeeAsHexStr, TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr,
    };
    use serde::Deserialize;
    use serde_with::serde_as;

    /// "Broadcasted" L2 transaction in requests the RPC API.
    ///
    /// "Broadcasted" transactions represent the data required to submit a new transaction.
    /// Notably, it's missing values computed during execution of the transaction, like
    /// transaction_hash or contract_address.
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields, tag = "type")]
    pub enum BroadcastedTransaction {
        #[serde(rename = "DECLARE")]
        Declare(BroadcastedDeclareTransaction),
        #[serde(rename = "INVOKE")]
        Invoke(BroadcastedInvokeTransaction),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(BroadcastedDeployAccountTransaction),
    }

    // TODO make sure deserialization is not ambiguous between V1 and V2
    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedDeclareTransaction {
        V0V1(BroadcastedDeclareTransactionV0V1),
        V2(BroadcastedDeclareTransactionV2),
    }

    impl<'de> serde::Deserialize<'de> for BroadcastedDeclareTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            match version.version.without_query_version() {
                0 | 1 => Ok(Self::V0V1(
                    BroadcastedDeclareTransactionV0V1::deserialize(&v)
                        .map_err(de::Error::custom)?,
                )),
                2 => Ok(Self::V2(
                    BroadcastedDeclareTransactionV2::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0, 1 or 2")),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeclareTransactionV0V1 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub contract_class: super::CairoContractClass,
        pub sender_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeclareTransactionV2 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub compiled_class_hash: CasmHash,
        pub contract_class: super::SierraContractClass,
        pub sender_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeployAccountTransaction {
        // Fields from BROADCASTED_TXN_COMMON_PROPERTIES
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        // Fields from DEPLOY_ACCOUNT_TXN_PROPERTIES
        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedInvokeTransaction {
        V0(BroadcastedInvokeTransactionV0),
        V1(BroadcastedInvokeTransactionV1),
    }

    impl<'de> Deserialize<'de> for BroadcastedInvokeTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de;

            #[serde_as]
            #[derive(Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                #[serde(default = "transaction_version_zero")]
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            match version.version.without_query_version() {
                0 => Ok(Self::V0(
                    BroadcastedInvokeTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                1 => Ok(Self::V1(
                    BroadcastedInvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _ => Err(de::Error::custom("version must be 0 or 1")),
            }
        }
    }

    const fn transaction_version_zero() -> TransactionVersion {
        TransactionVersion(ethers::types::H256::zero())
    }
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedInvokeTransactionV0 {
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default = "transaction_version_zero")]
        pub version: TransactionVersion,

        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        // This is a mistake in RPC specification v0.2. This field should not exist,
        // but since it is part of the spec we make it optional and then don't pass it
        // on to the gateway in the write API.
        pub nonce: Option<TransactionNonce>,

        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub calldata: Vec<CallParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedInvokeTransactionV1 {
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default = "transaction_version_zero")]
        pub version: TransactionVersion,

        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub sender_address: ContractAddress,
        pub calldata: Vec<CallParam>,
    }

    /// Contains parameters passed to `starknet_call`.
    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    // #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct Call {
        pub contract_address: ContractAddress,
        pub calldata: Vec<CallParam>,
        pub entry_point_selector: Option<EntryPoint>,
        /// EstimateFee hurry: it doesn't make any sense to use decimal numbers for one field
        #[serde(default)]
        #[serde_as(as = "Vec<TransactionSignatureElemAsDecimalStr>")]
        pub signature: Vec<TransactionSignatureElem>,
        /// EstimateFee hurry: max fee is needed if there's a signature
        #[serde_as(as = "FeeAsHexStr")]
        #[serde(default = "call_default_max_fee")]
        pub max_fee: Fee,
        /// EstimateFee hurry: transaction version might be interesting, might not be around for
        /// long
        #[serde_as(as = "TransactionVersionAsHexStr")]
        #[serde(default = "call_default_version")]
        pub version: TransactionVersion,
        #[serde(default = "call_default_nonce")]
        pub nonce: TransactionNonce,
    }

    const fn call_default_max_fee() -> Fee {
        Call::DEFAULT_MAX_FEE
    }

    const fn call_default_version() -> TransactionVersion {
        Call::DEFAULT_VERSION
    }

    const fn call_default_nonce() -> TransactionNonce {
        Call::DEFAULT_NONCE
    }

    impl Call {
        pub const DEFAULT_MAX_FEE: Fee = Fee(ethers::types::H128::zero());
        pub const DEFAULT_VERSION: TransactionVersion =
            TransactionVersion(ethers::types::H256::zero());
        pub const DEFAULT_NONCE: TransactionNonce = TransactionNonce(stark_hash::Felt::ZERO);
    }

    #[cfg(test)]
    mod tests {
        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../fixtures/0.50.0/", $file_name))
                    .replace(&[' ', '\n'], "")
            };
        }

        /// The aim of these tests is to check if deserialization works correctly
        /// **without resorting to serialization to prepare the test data**,
        /// which in itself could contain an "opposite phase" bug that cancels out.
        ///
        /// Serialization is tested btw, because the fixture and the data is already available.
        ///
        /// These tests were added due to recurring regressions stemming from, among others:
        /// - `serde(flatten)` and it's side-effects (for example when used in conjunction with `skip_serializing_none`),
        /// - `*AsDecimalStr*` creeping in from `sequencer::reply` as opposed to spec.
        mod serde {
            use super::super::*;
            use crate::v02::types::{
                CairoContractClass, ContractEntryPoints, SierraContractClass, SierraEntryPoint,
                SierraEntryPoints,
            };
            use pathfinder_common::felt;
            use pretty_assertions::assert_eq;

            #[test]
            fn broadcasted_transaction() {
                let contract_class = CairoContractClass {
                    program: "program".to_owned(),
                    entry_points_by_type: ContractEntryPoints {
                        constructor: vec![],
                        external: vec![],
                        l1_handler: vec![],
                    },
                    abi: None,
                };
                let txs = vec![
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V0V1(
                        BroadcastedDeclareTransactionV0V1 {
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x5)),
                            version: TransactionVersion(ethers::types::H256::from_low_u64_be(0x1)),
                            signature: vec![TransactionSignatureElem(felt!("0x7"))],
                            nonce: TransactionNonce(felt!("0x8")),
                            contract_class,
                            sender_address: ContractAddress::new_or_panic(felt!("0xa")),
                        },
                    )),
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
                        BroadcastedDeclareTransactionV2 {
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x51)),
                            version: TransactionVersion(ethers::types::H256::from_low_u64_be(0x2)),
                            signature: vec![TransactionSignatureElem(felt!("0x71"))],
                            nonce: TransactionNonce(felt!("0x81")),
                            compiled_class_hash: CasmHash(felt!("0x91")),
                            contract_class: SierraContractClass {
                                sierra_program: vec![felt!("0x4"), felt!("0x5")],
                                contract_class_version: "0.1.0".to_owned(),
                                entry_points_by_type: SierraEntryPoints {
                                    constructor: vec![SierraEntryPoint {
                                        function_idx: 1,
                                        selector: felt!("0x1"),
                                    }],
                                    external: vec![SierraEntryPoint {
                                        function_idx: 2,
                                        selector: felt!("0x2"),
                                    }],
                                    l1_handler: vec![SierraEntryPoint {
                                        function_idx: 3,
                                        selector: felt!("0x3"),
                                    }],
                                },
                                abi: Some(r#"[{"type":"function","name":"foo"}]"#.to_owned()),
                            },
                            sender_address: ContractAddress::new_or_panic(felt!("0xa1")),
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                        BroadcastedInvokeTransactionV0 {
                            version: TransactionVersion(ethers::types::H256::zero()),
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x6)),
                            signature: vec![TransactionSignatureElem(felt!("0x7"))],
                            nonce: Some(TransactionNonce(felt!("0x8"))),
                            contract_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                            entry_point_selector: EntryPoint(felt!("0xe")),
                            calldata: vec![CallParam(felt!("0xff"))],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion(ethers::types::H256::from_low_u64_be(1)),
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x6)),
                            signature: vec![TransactionSignatureElem(felt!("0x7"))],
                            nonce: TransactionNonce(felt!("0x8")),
                            sender_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                            calldata: vec![CallParam(felt!("0xff"))],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x6)),
                            signature: vec![TransactionSignatureElem(felt!("0x7"))],
                            nonce: TransactionNonce(felt!("0x8")),
                            sender_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                            calldata: vec![CallParam(felt!("0xff"))],
                        },
                    )),
                ];

                let json_fixture = fixture!("broadcasted_transactions.json");

                assert_eq!(serde_json::to_string(&txs).unwrap(), json_fixture);
                assert_eq!(
                    serde_json::from_str::<Vec<BroadcastedTransaction>>(&json_fixture).unwrap(),
                    txs
                );
            }
        }
    }
}

/// Groups all strictly output types of the RPC API.
pub mod reply {
    // At the moment both reply types are the same for get_code, hence the re-export
    use crate::felt::{RpcFelt, RpcFelt251};
    use pathfinder_common::{
        CallParam, CasmHash, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
        EntryPoint, Fee, StarknetTransactionHash, TransactionNonce, TransactionSignatureElem,
        TransactionVersion,
    };
    use pathfinder_serde::{FeeAsHexStr, TransactionVersionAsHexStr};
    use serde::{Deserialize, Serialize};
    use serde_with::serde_as;
    use starknet_gateway_types::reply::transaction::Transaction as GatewayTransaction;
    use std::convert::From;

    /// L2 transaction as returned by the RPC API.
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(tag = "type")]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "INVOKE")]
        Invoke(InvokeTransaction),
        // FIXME regenesis: remove Deploy txn type after regenesis
        // We are keeping this type of transaction until regenesis
        // only to support older pre-0.11.0 blocks
        #[serde(rename = "DEPLOY")]
        Deploy(DeployTransaction),
        #[serde(rename = "DEPLOY_ACCOUNT")]
        DeployAccount(DeployAccountTransaction),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransaction),
    }

    impl Transaction {
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Transaction::Declare(DeclareTransaction::V0(declare)) => declare.common.hash,
                Transaction::Declare(DeclareTransaction::V1(declare)) => declare.common.hash,
                Transaction::Declare(DeclareTransaction::V2(declare)) => declare.common.hash,
                Transaction::Invoke(InvokeTransaction::V0(invoke)) => invoke.common.hash,
                Transaction::Invoke(InvokeTransaction::V1(invoke)) => invoke.common.hash,
                Transaction::Deploy(deploy) => deploy.hash,
                Transaction::DeployAccount(deploy_account) => deploy_account.common.hash,
                Transaction::L1Handler(l1_handler) => l1_handler.hash,
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonTransactionProperties {
        #[serde(rename = "transaction_hash")]
        #[serde_as(as = "RpcFelt")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub signature: Vec<TransactionSignatureElem>,
        #[serde_as(as = "RpcFelt")]
        pub nonce: TransactionNonce,
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

    #[cfg(any(test, feature = "rpc-full-serde"))]
    impl<'de> serde::Deserialize<'de> for DeclareTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use ethers::types::H256;
            use serde::de;

            fn transaction_version_one() -> TransactionVersion {
                TransactionVersion(H256::from_low_u64_be(1))
            }

            #[serde_as]
            #[derive(serde::Deserialize)]
            struct Version {
                #[serde_as(as = "TransactionVersionAsHexStr")]
                #[serde(default = "transaction_version_one")]
                pub version: TransactionVersion,
            }

            let mut v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            // remove "version", since v1 and v2 transactions use deny_unknown_fields
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

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareTransactionV0V1 {
        #[serde(flatten)]
        pub common: CommonDeclareInvokeTransactionProperties,

        // DECLARE_TXN_V0
        // DECLARE_TXN_V1
        #[serde_as(as = "RpcFelt")]
        pub class_hash: ClassHash,
        #[serde_as(as = "RpcFelt251")]
        pub sender_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareTransactionV2 {
        #[serde(flatten)]
        pub common: CommonDeclareInvokeTransactionProperties,

        // DECLARE_TXN_V2
        #[serde_as(as = "RpcFelt")]
        pub class_hash: ClassHash,
        #[serde_as(as = "RpcFelt251")]
        pub sender_address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub compiled_class_hash: CasmHash,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployAccountTransaction {
        #[serde(flatten)]
        pub common: CommonTransactionProperties,

        // DEPLOY_ACCOUNT_TXN
        #[serde_as(as = "RpcFelt")]
        pub contract_address_salt: ContractAddressSalt,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub constructor_calldata: Vec<CallParam>,
        #[serde_as(as = "RpcFelt")]
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

    #[cfg(any(test, feature = "rpc-full-serde"))]
    impl<'de> serde::Deserialize<'de> for InvokeTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use ethers::types::H256;
            use serde::de;

            const VERSION_0: H256 = H256::zero();
            const fn transaction_version_zero() -> TransactionVersion {
                TransactionVersion(VERSION_0)
            }

            #[serde_as]
            #[derive(serde::Deserialize)]
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
                TransactionVersion(x) if x == VERSION_0 => Ok(Self::V0(
                    InvokeTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                TransactionVersion(x) if x == H256::from_low_u64_be(1) => Ok(Self::V1(
                    InvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _v => Err(de::Error::custom("version must be 0 or 1")),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransactionV0 {
        #[serde(flatten)]
        pub common: CommonDeclareInvokeTransactionProperties,

        // INVOKE_TXN_V0
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub entry_point_selector: EntryPoint,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub calldata: Vec<CallParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransactionV1 {
        #[serde(flatten)]
        pub common: CommonDeclareInvokeTransactionProperties,

        // INVOKE_TXN_V1
        #[serde_as(as = "RpcFelt251")]
        pub sender_address: ContractAddress,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub calldata: Vec<CallParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    // The same as `CommonTransactionProperties` except that it doesn't have version.
    //
    // Version is now a property of the type embedding common properties.
    pub struct CommonDeclareInvokeTransactionProperties {
        #[serde(rename = "transaction_hash")]
        #[serde_as(as = "RpcFelt")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub signature: Vec<TransactionSignatureElem>,
        #[serde_as(as = "RpcFelt")]
        pub nonce: TransactionNonce,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployTransaction {
        // DEPLOY_TXN
        #[serde(rename = "transaction_hash")]
        #[serde_as(as = "RpcFelt")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "RpcFelt")]
        pub class_hash: ClassHash,

        // DEPLOY_TXN_PROPERTIES
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        #[serde_as(as = "RpcFelt")]
        pub contract_address_salt: ContractAddressSalt,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct L1HandlerTransaction {
        // This part is a subset of CommonTransactionProperties
        #[serde(rename = "transaction_hash")]
        #[serde_as(as = "RpcFelt")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        #[serde_as(as = "RpcFelt")]
        pub nonce: TransactionNonce,

        // FUNCTION_CALL
        #[serde_as(as = "RpcFelt251")]
        pub contract_address: ContractAddress,
        #[serde_as(as = "RpcFelt")]
        pub entry_point_selector: EntryPoint,
        #[serde_as(as = "Vec<RpcFelt>")]
        pub calldata: Vec<CallParam>,
    }

    impl TryFrom<starknet_gateway_types::reply::Transaction> for Transaction {
        type Error = anyhow::Error;

        fn try_from(txn: starknet_gateway_types::reply::Transaction) -> Result<Self, Self::Error> {
            let txn = txn
                .transaction
                .ok_or_else(|| anyhow::anyhow!("Transaction not found."))?;

            Ok(txn.into())
        }
    }

    impl From<GatewayTransaction> for Transaction {
        fn from(txn: GatewayTransaction) -> Self {
            Self::from(&txn)
        }
    }

    impl From<&GatewayTransaction> for Transaction {
        fn from(txn: &GatewayTransaction) -> Self {
            use starknet_gateway_types::reply::transaction::DeclareTransaction as GatewayDeclare;
            match txn {
                GatewayTransaction::Invoke(txn) => {
                    match txn {
                        starknet_gateway_types::reply::transaction::InvokeTransaction::V0(txn) => {
                            Self::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                                common: CommonDeclareInvokeTransactionProperties {
                                    hash: txn.transaction_hash,
                                    max_fee: txn.max_fee,
                                    signature: txn.signature.clone(),
                                    // no `nonce` in v0 invoke transactions
                                    nonce: TransactionNonce(Default::default()),
                                },
                                contract_address: txn.sender_address,
                                entry_point_selector: txn.entry_point_selector,
                                calldata: txn.calldata.clone(),
                            }))
                        }
                        starknet_gateway_types::reply::transaction::InvokeTransaction::V1(txn) => {
                            Self::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
                                common: CommonDeclareInvokeTransactionProperties {
                                    hash: txn.transaction_hash,
                                    max_fee: txn.max_fee,
                                    signature: txn.signature.clone(),
                                    nonce: txn.nonce,
                                },
                                sender_address: txn.sender_address,
                                calldata: txn.calldata.clone(),
                            }))
                        }
                    }
                }
                GatewayTransaction::Declare(GatewayDeclare::V0(txn)) => {
                    Self::Declare(DeclareTransaction::V0(DeclareTransactionV0V1 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            signature: txn.signature.clone(),
                            nonce: txn.nonce,
                        },
                        class_hash: txn.class_hash,
                        sender_address: txn.sender_address,
                    }))
                }
                GatewayTransaction::Declare(GatewayDeclare::V1(txn)) => {
                    Self::Declare(DeclareTransaction::V1(DeclareTransactionV0V1 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            signature: txn.signature.clone(),
                            nonce: txn.nonce,
                        },
                        class_hash: txn.class_hash,
                        sender_address: txn.sender_address,
                    }))
                }
                GatewayTransaction::Declare(GatewayDeclare::V2(txn)) => {
                    Self::Declare(DeclareTransaction::V2(DeclareTransactionV2 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            signature: txn.signature.clone(),
                            nonce: txn.nonce,
                        },
                        class_hash: txn.class_hash,
                        sender_address: txn.sender_address,
                        compiled_class_hash: txn.compiled_class_hash,
                    }))
                }
                GatewayTransaction::Deploy(txn) => Self::Deploy(DeployTransaction {
                    hash: txn.transaction_hash,
                    class_hash: txn.class_hash,
                    version: txn.version,
                    contract_address_salt: txn.contract_address_salt,
                    constructor_calldata: txn.constructor_calldata.clone(),
                }),
                GatewayTransaction::DeployAccount(txn) => {
                    Self::DeployAccount(DeployAccountTransaction {
                        common: CommonTransactionProperties {
                            hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            version: txn.version,
                            signature: txn.signature.clone(),
                            nonce: txn.nonce,
                        },
                        contract_address_salt: txn.contract_address_salt,
                        constructor_calldata: txn.constructor_calldata.clone(),
                        class_hash: txn.class_hash,
                    })
                }
                GatewayTransaction::L1Handler(txn) => Self::L1Handler(L1HandlerTransaction {
                    hash: txn.transaction_hash,
                    version: txn.version,
                    nonce: txn.nonce,
                    contract_address: txn.contract_address,
                    entry_point_selector: txn.entry_point_selector,
                    calldata: txn.calldata.clone(),
                }),
            }
        }
    }

    /// L2 Block status as returned by the RPC API.
    #[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub enum BlockStatus {
        #[serde(rename = "PENDING")]
        Pending,
        #[serde(rename = "ACCEPTED_ON_L2")]
        AcceptedOnL2,
        #[serde(rename = "ACCEPTED_ON_L1")]
        AcceptedOnL1,
        #[serde(rename = "REJECTED")]
        Rejected,
    }

    impl From<starknet_gateway_types::reply::Status> for BlockStatus {
        fn from(status: starknet_gateway_types::reply::Status) -> Self {
            use starknet_gateway_types::reply::Status::*;

            match status {
                // TODO verify this mapping with Starkware
                AcceptedOnL1 => BlockStatus::AcceptedOnL1,
                AcceptedOnL2 => BlockStatus::AcceptedOnL2,
                NotReceived => BlockStatus::Rejected,
                Pending => BlockStatus::Pending,
                Received => BlockStatus::Pending,
                Rejected => BlockStatus::Rejected,
                Reverted => BlockStatus::Rejected,
                Aborted => BlockStatus::Rejected,
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    // #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct FeeEstimate {
        /// The Ethereum gas cost of the transaction
        #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
        pub gas_consumed: ethers::types::H256,
        /// The gas price (in gwei) that was used in the cost estimation (input to fee estimation)
        #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
        pub gas_price: ethers::types::H256,
        /// The estimated fee for the transaction (in gwei), product of gas_consumed and gas_price
        #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
        pub overall_fee: ethers::types::H256,
    }

    #[cfg(test)]
    mod tests {
        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../fixtures/0.50.0/", $file_name))
                    .replace(&[' ', '\n'], "")
            };
        }

        /// The aim of these tests is to check if serialization works correctly
        /// **without resorting to deserialization to prepare the test data**,
        /// which in itself could contain an "opposite phase" bug that cancels out.
        ///
        /// Deserialization is tested btw, because the fixture and the data is already available.
        ///
        /// These tests were added due to recurring regressions stemming from, among others:
        /// - `serde(flatten)` and it's side-effects (for example when used in conjunction with `skip_serializing_none`),
        /// - `*AsDecimalStr*` creeping in from `sequencer::reply` as opposed to spec.
        mod serde {
            use super::super::*;
            use pathfinder_common::felt;
            use pretty_assertions::assert_eq;

            #[test]
            fn transaction() {
                let transactions = vec![
                    Transaction::Declare(DeclareTransaction::V1(DeclareTransactionV0V1 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: StarknetTransactionHash(felt!("0x4")),
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x5)),
                            signature: vec![TransactionSignatureElem(felt!("0x7"))],
                            nonce: TransactionNonce(felt!("0x8")),
                        },
                        class_hash: ClassHash(felt!("0x9")),
                        sender_address: ContractAddress::new_or_panic(felt!("0xa")),
                    })),
                    Transaction::Declare(DeclareTransaction::V2(DeclareTransactionV2 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: StarknetTransactionHash(felt!("0x44")),
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x55)),
                            signature: vec![TransactionSignatureElem(felt!("0x77"))],
                            nonce: TransactionNonce(felt!("0x88")),
                        },
                        class_hash: ClassHash(felt!("0x90")),
                        sender_address: ContractAddress::new_or_panic(felt!("0xa0")),
                        compiled_class_hash: CasmHash(felt!("0xb0")),
                    })),
                    Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: StarknetTransactionHash(felt!("0xb")),
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x999)),
                            signature: vec![TransactionSignatureElem(felt!("0x777"))],
                            nonce: TransactionNonce(felt!("0xdd")),
                        },
                        contract_address: ContractAddress::new_or_panic(felt!("0xb")),
                        entry_point_selector: EntryPoint(felt!("0xc")),
                        calldata: vec![CallParam(felt!("0xd"))],
                    })),
                    Transaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: StarknetTransactionHash(felt!("0xbbb")),
                            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x9999)),
                            signature: vec![TransactionSignatureElem(felt!("0xeee"))],
                            nonce: TransactionNonce(felt!("0xde")),
                        },
                        sender_address: ContractAddress::new_or_panic(felt!("0xc")),
                        calldata: vec![CallParam(felt!("0xddd"))],
                    })),
                    Transaction::Deploy(DeployTransaction {
                        hash: StarknetTransactionHash(felt!("0xe")),
                        class_hash: ClassHash(felt!("0x10")),
                        version: TransactionVersion(ethers::types::H256::from_low_u64_be(1)),
                        contract_address_salt: ContractAddressSalt(felt!("0xee")),
                        constructor_calldata: vec![ConstructorParam(felt!("0x11"))],
                    }),
                    Transaction::L1Handler(L1HandlerTransaction {
                        hash: StarknetTransactionHash(felt!("0xf")),
                        version: TransactionVersion(ethers::types::H256::from_low_u64_be(1)),
                        nonce: TransactionNonce(felt!("0x8")),
                        contract_address: ContractAddress::new_or_panic(felt!("0xfff")),
                        entry_point_selector: EntryPoint(felt!("0xf")),
                        calldata: vec![CallParam(felt!("0xf"))],
                    }),
                ];

                assert_eq!(
                    serde_json::to_string(&transactions).unwrap(),
                    fixture!("transaction.json")
                );
                assert_eq!(
                    serde_json::from_str::<Vec<Transaction>>(&fixture!("transaction.json"))
                        .unwrap(),
                    transactions
                );
            }
        }
    }
}
