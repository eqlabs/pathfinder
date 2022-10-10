//! Common data structures used by the JSON-RPC API methods.

mod class;
pub use class::*;

/// Groups all strictly input types of the RPC API.
pub mod request {
    use crate::{
        core::{
            CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
            EntryPoint, Fee, TransactionNonce, TransactionSignatureElem, TransactionVersion,
        },
        rpc::serde::{FeeAsHexStr, TransactionVersionAsHexStr},
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
        #[serde(rename = "DEPLOY")]
        Deploy(BroadcastedDeployTransaction),
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeclareTransaction {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub contract_class: ClassHash,
        pub sender_address: ContractAddress,
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeployTransaction {
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<ConstructorParam>,

        /// The class of the contract that will be deployed.
        pub contract_class: ClassHash,
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
        TransactionVersion(web3::types::H256::zero())
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

    #[cfg(test)]
    mod tests {
        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../../fixtures/rpc/0.44.0/", $file_name))
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
            use crate::starkhash;
            use pretty_assertions::assert_eq;

            #[test]
            fn broadcasted_transaction() {
                let txs = vec![
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction {
                        max_fee: Fee(web3::types::H128::from_low_u64_be(0x5)),
                        version: TransactionVersion(web3::types::H256::from_low_u64_be(0x0)),
                        signature: vec![TransactionSignatureElem(starkhash!("07"))],
                        nonce: TransactionNonce(starkhash!("08")),
                        contract_class: ClassHash(starkhash!("09")),
                        sender_address: ContractAddress::new_or_panic(starkhash!("0a")),
                    }),
                    BroadcastedTransaction::Deploy(BroadcastedDeployTransaction {
                        version: TransactionVersion(web3::types::H256::from_low_u64_be(0x0)),
                        contract_address_salt: ContractAddressSalt(starkhash!("dd")),
                        constructor_calldata: vec![ConstructorParam(starkhash!("11"))],
                        contract_class: ClassHash(starkhash!("10")),
                    }),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                        BroadcastedInvokeTransactionV0 {
                            version: TransactionVersion(web3::types::H256::zero()),
                            max_fee: Fee(web3::types::H128::from_low_u64_be(0x6)),
                            signature: vec![TransactionSignatureElem(starkhash!("07"))],
                            nonce: Some(TransactionNonce(starkhash!("08"))),
                            contract_address: ContractAddress::new_or_panic(starkhash!("0aaa")),
                            entry_point_selector: EntryPoint(starkhash!("0e")),
                            calldata: vec![CallParam(starkhash!("ff"))],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion(web3::types::H256::from_low_u64_be(1)),
                            max_fee: Fee(web3::types::H128::from_low_u64_be(0x6)),
                            signature: vec![TransactionSignatureElem(starkhash!("07"))],
                            nonce: TransactionNonce(starkhash!("08")),
                            sender_address: ContractAddress::new_or_panic(starkhash!("0aaa")),
                            calldata: vec![CallParam(starkhash!("ff"))],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion(web3::types::H256(hex_literal::hex!(
                                "0000000000000000000000000000000100000000000000000000000000000001"
                            ))),
                            max_fee: Fee(web3::types::H128::from_low_u64_be(0x6)),
                            signature: vec![TransactionSignatureElem(starkhash!("07"))],
                            nonce: TransactionNonce(starkhash!("08")),
                            sender_address: ContractAddress::new_or_panic(starkhash!("0aaa")),
                            calldata: vec![CallParam(starkhash!("ff"))],
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
    use crate::{
        core::{
            CallParam, ClassHash, ConstructorParam, ContractAddress, ContractAddressSalt,
            EntryPoint, Fee, StarknetTransactionHash, TransactionNonce, TransactionSignatureElem,
            TransactionVersion,
        },
        rpc::serde::{FeeAsHexStr, TransactionVersionAsHexStr},
        sequencer,
    };
    use serde::Serialize;
    use serde_with::serde_as;
    use std::convert::From;

    /// L2 transaction as returned by the RPC API.
    ///
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(tag = "type")]
    pub enum Transaction {
        #[serde(rename = "DECLARE")]
        Declare(DeclareTransaction),
        #[serde(rename = "INVOKE")]
        Invoke(InvokeTransaction),
        #[serde(rename = "DEPLOY")]
        Deploy(DeployTransaction),
        #[serde(rename = "L1_HANDLER")]
        L1Handler(L1HandlerTransaction),
    }

    impl Transaction {
        pub fn hash(&self) -> StarknetTransactionHash {
            match self {
                Transaction::Declare(declare) => declare.common.hash,
                Transaction::Invoke(InvokeTransaction::V0(invoke)) => invoke.common.hash,
                Transaction::Invoke(InvokeTransaction::V1(invoke)) => invoke.common.hash,
                Transaction::Deploy(deploy) => deploy.hash,
                Transaction::L1Handler(l1_handler) => l1_handler.hash,
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct CommonTransactionProperties {
        #[serde(rename = "transaction_hash")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeclareTransaction {
        #[serde(flatten)]
        pub common: CommonTransactionProperties,

        // DECLARE_TXN
        pub class_hash: ClassHash,
        pub sender_address: ContractAddress,
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
            use serde::de;
            use web3::types::H256;

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
        pub common: CommonInvokeTransactionProperties,

        // INVOKE_TXN_V0
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub calldata: Vec<CallParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct InvokeTransactionV1 {
        #[serde(flatten)]
        pub common: CommonInvokeTransactionProperties,

        // INVOKE_TXN_V1
        pub sender_address: ContractAddress,
        pub calldata: Vec<CallParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    // The same as `CommonTransactionProperties` except that it doesn't have version.
    //
    // Version is now a property of the type embedding common properties.
    pub struct CommonInvokeTransactionProperties {
        #[serde(rename = "transaction_hash")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "FeeAsHexStr")]
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct DeployTransaction {
        // DEPLOY_TXN
        #[serde(rename = "transaction_hash")]
        pub hash: StarknetTransactionHash,
        pub class_hash: ClassHash,

        // DEPLOY_TXN_PROPERTIES
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<ConstructorParam>,
    }

    #[serde_as]
    #[derive(Clone, Debug, Serialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    pub struct L1HandlerTransaction {
        // This part is a subset of CommonTransactionProperties
        #[serde(rename = "transaction_hash")]
        pub hash: StarknetTransactionHash,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub nonce: TransactionNonce,

        // FUNCTION_CALL
        pub contract_address: ContractAddress,
        pub entry_point_selector: EntryPoint,
        pub calldata: Vec<CallParam>,
    }

    impl TryFrom<sequencer::reply::Transaction> for Transaction {
        type Error = anyhow::Error;

        fn try_from(txn: sequencer::reply::Transaction) -> Result<Self, Self::Error> {
            let txn = txn
                .transaction
                .ok_or_else(|| anyhow::anyhow!("Transaction not found."))?;

            Ok(txn.into())
        }
    }

    impl From<sequencer::reply::transaction::Transaction> for Transaction {
        fn from(txn: sequencer::reply::transaction::Transaction) -> Self {
            Self::from(&txn)
        }
    }

    impl From<&sequencer::reply::transaction::Transaction> for Transaction {
        fn from(txn: &sequencer::reply::transaction::Transaction) -> Self {
            match txn {
                sequencer::reply::transaction::Transaction::Invoke(txn) => {
                    match txn {
                        sequencer::reply::transaction::InvokeTransaction::V0(txn) => {
                            Self::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                                common: CommonInvokeTransactionProperties {
                                    hash: txn.transaction_hash,
                                    max_fee: txn.max_fee,
                                    signature: txn.signature.clone(),
                                    // no `nonce` in v0 invoke transactions
                                    nonce: TransactionNonce(Default::default()),
                                },
                                contract_address: txn.contract_address,
                                entry_point_selector: txn.entry_point_selector,
                                calldata: txn.calldata.clone(),
                            }))
                        }
                        sequencer::reply::transaction::InvokeTransaction::V1(txn) => {
                            Self::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
                                common: CommonInvokeTransactionProperties {
                                    hash: txn.transaction_hash,
                                    max_fee: txn.max_fee,
                                    signature: txn.signature.clone(),
                                    nonce: txn.nonce,
                                },
                                sender_address: txn.contract_address,
                                calldata: txn.calldata.clone(),
                            }))
                        }
                    }
                }
                sequencer::reply::transaction::Transaction::Declare(txn) => {
                    Self::Declare(DeclareTransaction {
                        common: CommonTransactionProperties {
                            hash: txn.transaction_hash,
                            max_fee: txn.max_fee,
                            version: txn.version,
                            signature: txn.signature.clone(),
                            nonce: txn.nonce,
                        },
                        class_hash: txn.class_hash,
                        sender_address: txn.sender_address,
                    })
                }
                sequencer::reply::transaction::Transaction::Deploy(txn) => {
                    Self::Deploy(DeployTransaction {
                        hash: txn.transaction_hash,
                        class_hash: txn.class_hash,
                        version: txn.version,
                        contract_address_salt: txn.contract_address_salt,
                        constructor_calldata: txn.constructor_calldata.clone(),
                    })
                }
                sequencer::reply::transaction::Transaction::L1Handler(txn) => {
                    Self::L1Handler(L1HandlerTransaction {
                        hash: txn.transaction_hash,
                        version: txn.version,
                        nonce: txn.nonce,
                        contract_address: txn.contract_address,
                        entry_point_selector: txn.entry_point_selector,
                        calldata: txn.calldata.clone(),
                    })
                }
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

    impl From<sequencer::reply::Status> for BlockStatus {
        fn from(status: sequencer::reply::Status) -> Self {
            match status {
                // TODO verify this mapping with Starkware
                sequencer::reply::Status::AcceptedOnL1 => BlockStatus::AcceptedOnL1,
                sequencer::reply::Status::AcceptedOnL2 => BlockStatus::AcceptedOnL2,
                sequencer::reply::Status::NotReceived => BlockStatus::Rejected,
                sequencer::reply::Status::Pending => BlockStatus::Pending,
                sequencer::reply::Status::Received => BlockStatus::Pending,
                sequencer::reply::Status::Rejected => BlockStatus::Rejected,
                sequencer::reply::Status::Reverted => BlockStatus::Rejected,
                sequencer::reply::Status::Aborted => BlockStatus::Rejected,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        macro_rules! fixture {
            ($file_name:literal) => {
                include_str!(concat!("../../../fixtures/rpc/0.44.0/", $file_name))
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
            use crate::starkhash;
            use pretty_assertions::assert_eq;

            #[test]
            fn transaction() {
                let common = CommonTransactionProperties {
                    hash: StarknetTransactionHash(starkhash!("04")),
                    max_fee: Fee(web3::types::H128::from_low_u64_be(0x5)),
                    version: TransactionVersion(web3::types::H256::from_low_u64_be(0x0)),
                    signature: vec![TransactionSignatureElem(starkhash!("07"))],
                    nonce: TransactionNonce(starkhash!("08")),
                };

                let transactions = vec![
                    Transaction::Declare(DeclareTransaction {
                        common: common.clone(),
                        class_hash: ClassHash(starkhash!("09")),
                        sender_address: ContractAddress::new_or_panic(starkhash!("0a")),
                    }),
                    Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                        common: CommonInvokeTransactionProperties {
                            hash: StarknetTransactionHash(starkhash!("0b")),
                            max_fee: Fee(web3::types::H128::from_low_u64_be(0x999)),
                            signature: vec![TransactionSignatureElem(starkhash!("0777"))],
                            nonce: TransactionNonce(starkhash!("dd")),
                        },
                        contract_address: ContractAddress::new_or_panic(starkhash!("0b")),
                        entry_point_selector: EntryPoint(starkhash!("0c")),
                        calldata: vec![CallParam(starkhash!("0d"))],
                    })),
                    Transaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
                        common: CommonInvokeTransactionProperties {
                            hash: StarknetTransactionHash(starkhash!("0bbb")),
                            max_fee: Fee(web3::types::H128::from_low_u64_be(0x9999)),
                            signature: vec![TransactionSignatureElem(starkhash!("0eee"))],
                            nonce: TransactionNonce(starkhash!("de")),
                        },
                        sender_address: ContractAddress::new_or_panic(starkhash!("0c")),
                        calldata: vec![CallParam(starkhash!("0ddd"))],
                    })),
                    Transaction::Deploy(DeployTransaction {
                        hash: StarknetTransactionHash(starkhash!("0e")),
                        class_hash: ClassHash(starkhash!("10")),
                        version: TransactionVersion(web3::types::H256::from_low_u64_be(1)),
                        contract_address_salt: ContractAddressSalt(starkhash!("ee")),
                        constructor_calldata: vec![ConstructorParam(starkhash!("11"))],
                    }),
                    Transaction::L1Handler(L1HandlerTransaction {
                        hash: StarknetTransactionHash(starkhash!("0f")),
                        version: TransactionVersion(web3::types::H256::from_low_u64_be(1)),
                        nonce: common.nonce,
                        contract_address: ContractAddress::new_or_panic(starkhash!("0fff")),
                        entry_point_selector: EntryPoint(starkhash!("0f")),
                        calldata: vec![CallParam(starkhash!("0f"))],
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
