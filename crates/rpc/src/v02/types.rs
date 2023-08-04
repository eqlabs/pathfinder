//! Common data structures used by the JSON-RPC API methods.

pub(crate) mod class;
pub use class::*;
pub mod syncing;

/// Groups all strictly input types of the RPC API.
pub mod request {
    use std::ops::Rem;

    use pathfinder_common::{
        CallParam, CasmHash, ChainId, ClassHash, ContractAddress, ContractAddressSalt, EntryPoint,
        Fee, TransactionHash, TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_serde::{TransactionSignatureElemAsDecimalStr, TransactionVersionAsHexStr};
    use serde::Deserialize;
    use serde_with::serde_as;
    use stark_hash::{Felt, HashChain};
    use starknet_gateway_types::transaction_hash::compute_txn_hash;

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

    impl BroadcastedTransaction {
        pub fn into_invoke(self) -> Option<BroadcastedInvokeTransaction> {
            match self {
                Self::Invoke(x) => Some(x),
                _ => None,
            }
        }

        pub fn into_declare(self) -> Option<BroadcastedDeclareTransaction> {
            match self {
                Self::Declare(x) => Some(x),
                _ => None,
            }
        }

        pub fn into_deploy_account(self) -> Option<BroadcastedDeployAccountTransaction> {
            match self {
                Self::DeployAccount(x) => Some(x),
                _ => None,
            }
        }

        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: Option<ClassHash>,
        ) -> TransactionHash {
            match self {
                BroadcastedTransaction::Declare(tx) => {
                    let class_hash =
                        class_hash.expect("Declare transactions should supply class hash");
                    match tx {
                        BroadcastedDeclareTransaction::V0(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                        BroadcastedDeclareTransaction::V1(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                        BroadcastedDeclareTransaction::V2(tx) => {
                            tx.transaction_hash(chain_id, class_hash)
                        }
                    }
                }
                BroadcastedTransaction::Invoke(tx) => match tx {
                    BroadcastedInvokeTransaction::V1(tx) => tx.transaction_hash(chain_id),
                },
                BroadcastedTransaction::DeployAccount(tx) => tx.transaction_hash(chain_id),
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedDeclareTransaction {
        V0(BroadcastedDeclareTransactionV0),
        V1(BroadcastedDeclareTransactionV1),
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
                0 => Ok(Self::V0(
                    BroadcastedDeclareTransactionV0::deserialize(&v).map_err(de::Error::custom)?,
                )),
                1 => Ok(Self::V1(
                    BroadcastedDeclareTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
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
    pub struct BroadcastedDeclareTransactionV0 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,

        pub contract_class: super::CairoContractClass,
        pub sender_address: ContractAddress,
    }

    impl BroadcastedDeclareTransactionV0 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            compute_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                None,
                HashChain::default().finalize(),
                None,
                chain_id,
                class_hash,
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeclareTransactionV1 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub contract_class: super::CairoContractClass,
        pub sender_address: ContractAddress,
    }

    impl BroadcastedDeclareTransactionV1 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            compute_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                None,
                {
                    let mut h = HashChain::default();
                    h.update(class_hash.0);
                    h.finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                None,
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeclareTransactionV2 {
        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub compiled_class_hash: CasmHash,
        pub contract_class: super::SierraContractClass,
        pub sender_address: ContractAddress,
    }

    impl BroadcastedDeclareTransactionV2 {
        pub fn transaction_hash(
            &self,
            chain_id: ChainId,
            class_hash: ClassHash,
        ) -> TransactionHash {
            compute_txn_hash(
                b"declare",
                self.version,
                self.sender_address,
                None,
                {
                    let mut h = HashChain::default();
                    h.update(class_hash.0);
                    h.finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                Some(self.compiled_class_hash),
            )
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedDeployAccountTransaction {
        // Fields from BROADCASTED_TXN_COMMON_PROPERTIES
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        // Fields from DEPLOY_ACCOUNT_TXN_PROPERTIES
        pub contract_address_salt: ContractAddressSalt,
        pub constructor_calldata: Vec<CallParam>,
        pub class_hash: ClassHash,
    }

    impl BroadcastedDeployAccountTransaction {
        pub fn deployed_contract_address(&self) -> ContractAddress {
            let constructor_calldata_hash = self
                .constructor_calldata
                .iter()
                .fold(HashChain::default(), |mut h, param| {
                    h.update(param.0);
                    h
                })
                .finalize();

            let contract_address = [
                Felt::from_be_slice(b"STARKNET_CONTRACT_ADDRESS").expect("prefix is convertible"),
                Felt::ZERO,
                self.contract_address_salt.0,
                self.class_hash.0,
                constructor_calldata_hash,
            ]
            .into_iter()
            .fold(HashChain::default(), |mut h, e| {
                h.update(e);
                h
            })
            .finalize();

            // Contract addresses are _less than_ 2**251 - 256
            let contract_address =
                primitive_types::U256::from_big_endian(contract_address.as_be_bytes());
            let max_address = primitive_types::U256::from_str_radix(
                "0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00",
                16,
            )
            .unwrap();

            let contract_address = contract_address.rem(max_address);
            let mut b = [0u8; 32];
            contract_address.to_big_endian(&mut b);
            let contract_address = Felt::from_be_slice(&b).unwrap();

            ContractAddress::new_or_panic(contract_address)
        }

        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            let contract_address = self.deployed_contract_address();

            compute_txn_hash(
                b"deploy_account",
                self.version,
                contract_address,
                None,
                {
                    let mut h = HashChain::default();
                    h.update(self.class_hash.0);
                    h.update(self.contract_address_salt.0);
                    h = self
                        .constructor_calldata
                        .iter()
                        .fold(h, |mut h, constructor_param| {
                            h.update(constructor_param.0);
                            h
                        });
                    h.finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                None,
            )
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    #[cfg_attr(
        any(test, feature = "rpc-full-serde"),
        derive(serde::Serialize),
        serde(untagged)
    )]
    pub enum BroadcastedInvokeTransaction {
        V1(BroadcastedInvokeTransactionV1),
    }

    impl BroadcastedInvokeTransaction {
        pub fn into_v1(self) -> Option<BroadcastedInvokeTransactionV1> {
            match self {
                Self::V1(x) => Some(x),
            }
        }
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
                pub version: TransactionVersion,
            }

            let v = serde_json::Value::deserialize(deserializer)?;
            let version = Version::deserialize(&v).map_err(de::Error::custom)?;
            match version.version.without_query_version() {
                1 => Ok(Self::V1(
                    BroadcastedInvokeTransactionV1::deserialize(&v).map_err(de::Error::custom)?,
                )),
                _ => Err(de::Error::custom("version must be 1")),
            }
        }
    }

    #[serde_as]
    #[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
    #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Serialize))]
    #[serde(deny_unknown_fields)]
    pub struct BroadcastedInvokeTransactionV1 {
        #[serde_as(as = "TransactionVersionAsHexStr")]
        pub version: TransactionVersion,

        // BROADCASTED_TXN_COMMON_PROPERTIES: ideally this should just be included
        // here in a flattened struct, but `flatten` doesn't work with
        // `deny_unknown_fields`: https://serde.rs/attr-flatten.html#struct-flattening
        pub max_fee: Fee,
        pub signature: Vec<TransactionSignatureElem>,
        pub nonce: TransactionNonce,

        pub sender_address: ContractAddress,
        pub calldata: Vec<CallParam>,
    }

    impl BroadcastedInvokeTransactionV1 {
        pub fn transaction_hash(&self, chain_id: ChainId) -> TransactionHash {
            compute_txn_hash(
                b"invoke",
                self.version,
                self.sender_address,
                None,
                {
                    self.calldata
                        .iter()
                        .fold(HashChain::default(), |mut hh, call_param| {
                            hh.update(call_param.0);
                            hh
                        })
                        .finalize()
                },
                Some(self.max_fee),
                chain_id,
                self.nonce,
                None,
            )
        }
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
        pub const DEFAULT_MAX_FEE: Fee = Fee::ZERO;
        pub const DEFAULT_VERSION: TransactionVersion =
            TransactionVersion(primitive_types::H256::zero());
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
            use pathfinder_common::macro_prelude::*;
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
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(
                        BroadcastedDeclareTransactionV1 {
                            max_fee: fee!("0x5"),
                            version: TransactionVersion(primitive_types::H256::from_low_u64_be(
                                0x1,
                            )),
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            contract_class,
                            sender_address: contract_address!("0xa"),
                        },
                    )),
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(
                        BroadcastedDeclareTransactionV2 {
                            max_fee: fee!("0x51"),
                            version: TransactionVersion(primitive_types::H256::from_low_u64_be(
                                0x2,
                            )),
                            signature: vec![transaction_signature_elem!("0x71")],
                            nonce: transaction_nonce!("0x81"),
                            compiled_class_hash: casm_hash!("0x91"),
                            contract_class: SierraContractClass {
                                sierra_program: vec![felt!("0x4"), felt!("0x5")],
                                contract_class_version: "0.1.0".into(),
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
                                abi: r#"[{"type":"function","name":"foo"}]"#.into(),
                            },
                            sender_address: contract_address!("0xa1"),
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion(primitive_types::H256::from_low_u64_be(1)),
                            max_fee: fee!("0x6"),
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            sender_address: contract_address!("0xaaa"),
                            calldata: vec![call_param!("0xff")],
                        },
                    )),
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                        BroadcastedInvokeTransactionV1 {
                            version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                            max_fee: fee!("0x6"),
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                            sender_address: contract_address!("0xaaa"),
                            calldata: vec![call_param!("0xff")],
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

        mod transaction_hash {
            use crate::v02::types::ContractClass;

            use super::super::*;

            use pathfinder_common::macro_prelude::*;

            #[test]
            fn declare_v1() {
                // https://testnet.starkscan.co/tx/0x05c72f6fdbbddde03a9921e520273b4ff940d01f118793e7f9ed56f5a74cbfc0
                let contract_class = ContractClass::from_definition_bytes(starknet_gateway_test_fixtures::class_definitions::CAIRO_TESTNET_0331118F4E4EB8A8DDB0F4493E09612E380EF527991C49A15C42574AB48DD747).unwrap().as_cairo().unwrap();

                let tx = BroadcastedDeclareTransactionV1 {
                    max_fee: fee!("0x6c8737288fe"),
                    version: TransactionVersion::ONE,
                    signature: vec![
                        transaction_signature_elem!(
                            "0x1c7f348434157f917dcdb4ab62d32b26be5f859fd84502043bb6c3ed85bc53f"
                        ),
                        transaction_signature_elem!(
                            "0xd3f3c40d988f9b6471e371f45419ac0354cde6aa26b885a83775ded8a4f1ae"
                        ),
                    ],
                    nonce: transaction_nonce!("0x8c"),
                    contract_class,
                    sender_address: contract_address!(
                        "0x138aefdb281051e0cb93199bc88f133c2ba83cbd50fe6fc984b5588b087917c"
                    ),
                };

                let transaction =
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V1(tx));
                assert_eq!(
                    transaction.transaction_hash(ChainId::TESTNET, Some(starknet_gateway_test_fixtures::class_definitions::CAIRO_TESTNET_0331118F4E4EB8A8DDB0F4493E09612E380EF527991C49A15C42574AB48DD747_CLASS_HASH)),
                    transaction_hash!(
                        "0x05c72f6fdbbddde03a9921e520273b4ff940d01f118793e7f9ed56f5a74cbfc0"
                    )
                );
            }

            #[test]
            fn declare_v2() {
                // https://testnet.starkscan.co/tx/0x055ab647f4aee18d9981fbe251ccf57a553ec3841b57e2f74a434b2aa6ba0513
                let contract_class = ContractClass::from_definition_bytes(starknet_gateway_test_fixtures::class_definitions::SIERRA_TESTNET_02E62A7336B45FA98668A6275168CE42B085665A9EC16B100D895968691A0BDC).unwrap().as_sierra().unwrap();

                let tx = BroadcastedDeclareTransactionV2 {
                    max_fee: fee!("0x5a1cdc61aaf"),
                    version: TransactionVersion::TWO,
                    signature: vec![
                        transaction_signature_elem!(
                            "0x3b871618705b5ba52e1f93dcacf4a1e4ffb465897cff33d4ac82de449f9f364"
                        ),
                        transaction_signature_elem!(
                            "0x51a63df7e26778461a275b827966a44ea279605958dde0be34f956f4818e06e"
                        ),
                    ],
                    nonce: transaction_nonce!("0x1b"),
                    compiled_class_hash: casm_hash!(
                        "0x6b04d63f49e58baea2ec5dda9c21c66cd220e3826fb6374d11de7d672d04e07"
                    ),
                    contract_class,
                    sender_address: contract_address!(
                        "0x69b5d9662b45fe3bc6602ff519c8449e30cadf3eb2617ce46ca2551ded86ef3"
                    ),
                };

                let transaction =
                    BroadcastedTransaction::Declare(BroadcastedDeclareTransaction::V2(tx));
                assert_eq!(
                transaction.transaction_hash(ChainId::TESTNET, Some(starknet_gateway_test_fixtures::class_definitions::SIERRA_TESTNET_02E62A7336B45FA98668A6275168CE42B085665A9EC16B100D895968691A0BDC_CLASS_HASH)),
                transaction_hash!(
                    "0x055ab647f4aee18d9981fbe251ccf57a553ec3841b57e2f74a434b2aa6ba0513"
                )
            );
            }

            #[test]
            fn invoke_v1() {
                // https://testnet.starkscan.co/tx/0x025d11606f1a73602099a359e4b5da03c45372a92eb0c9be2800c3123e7a26aa
                let tx = BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE,
                    max_fee: fee!("0x2386f26fc10000"),
                    signature: vec![
                        transaction_signature_elem!(
                            "0x68ff0404a75dd45b25cfb43d8d5c6747ab602368a003a8acea4e28fae0c03d6"
                        ),
                        transaction_signature_elem!(
                            "0x5c5e346a92c58239c68fbc2756aa0a2c76f9af198313c397e96f78ef273a596"
                        ),
                    ],
                    nonce: transaction_nonce!("0xaa23"),
                    sender_address: contract_address!(
                        "0x58b7ee817bd2978c7657d05d3131e83e301ed1aa79d5ad16f01925fd52d1da7"
                    ),
                    calldata: vec![
                        call_param!("0x1"),
                        call_param!(
                            "0x51c6428132045e01eb6a779be05f0e3b88760cadb5a4ec988d9ab2729b12a67"
                        ),
                        call_param!(
                            "0x2d7cf5d5a324a320f9f37804b1615a533fde487400b41af80f13f7ac5581325"
                        ),
                        call_param!("0x0"),
                        call_param!("0x4"),
                        call_param!("0x4"),
                        call_param!("0xdc7f0b6facd8eabbac6d1c2c1cff73bece8dbbda"),
                        call_param!("0x2"),
                        call_param!(
                            "0x480817f9e0a8d41850dc4875df76a4990c7f6772221bb2a06a414b22a5fc709"
                        ),
                        call_param!(
                            "0x59f131a9ff4eb312f32ba82461d2165c12bd54d9f9d97935d7778fe9c3f82c1"
                        ),
                    ],
                };

                let transaction =
                    BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(tx));
                assert_eq!(
                    transaction.transaction_hash(ChainId::TESTNET, None),
                    transaction_hash!(
                        "0x25d11606f1a73602099a359e4b5da03c45372a92eb0c9be2800c3123e7a26aa"
                    )
                );
            }

            #[test]
            fn deploy_account() {
                // https://testnet.starkscan.co/tx/0x0167486c4202020e510809ae1703111186de8d36a606ce948dcfab910cc18713
                let class_hash = class_hash!(
                    "0x25ec026985a3bf9d0cc1fe17326b245dfdc3ff89b8fde106542a3ea56c5a918"
                );
                let tx = BroadcastedDeployAccountTransaction {
                    version: TransactionVersion::ONE,
                    max_fee: fee!("0x15e1e7c9a7a0"),
                    signature: vec![
                        transaction_signature_elem!(
                            "0x32628e08929f7cee80f82c4663546057868f7f50899df1b7b8c61d9eddbb111"
                        ),
                        transaction_signature_elem!(
                            "0x2fd6211adc5898cc6df61e5aeb13b1bfa79a88716cc5d8b6b2a0afffc7ccd83"
                        ),
                        transaction_signature_elem!(
                            "0x5ec0d11dc1588a68f04c6b4a01c67b4f772ed364cfb26ecca5f5f4d2462fafd"
                        ),
                    ],
                    nonce: transaction_nonce!("0x0"),
                    contract_address_salt: contract_address_salt!(
                        "0x32628e08929f7cee80f82c4663546057868f7f50899df1b7b8c61d9eddbb111"
                    ),
                    constructor_calldata: vec![
                        call_param!(
                            "0x4ba0f956a26b5e0d7e491661a0c56a6eb0fc25d49912677de09439673c3c828"
                        ),
                        call_param!(
                            "0x79dc0da7c54b95f10aa182ad0a46400db63156920adb65eca2654c0945a463"
                        ),
                        call_param!("0x4"),
                        call_param!("0x2"),
                        call_param!("0x2"),
                        call_param!(
                            "0x32628e08929f7cee80f82c4663546057868f7f50899df1b7b8c61d9eddbb111"
                        ),
                        call_param!(
                            "0x235d794ee259b38bfec8fabb5efecf7b17f53e5be3d830ec0d076fb8b101fae"
                        ),
                    ],
                    class_hash,
                };

                assert_eq!(
                    tx.deployed_contract_address(),
                    contract_address!(
                        "0x53b40d3140504657fa11be5b65ef139bf9b82dba6691a1b0c84be85fad5f9e2"
                    )
                );

                let transaction = BroadcastedTransaction::DeployAccount(tx);
                assert_eq!(
                    transaction.transaction_hash(ChainId::TESTNET, Some(class_hash)),
                    transaction_hash!(
                        "0x0167486c4202020e510809ae1703111186de8d36a606ce948dcfab910cc18713"
                    )
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
        EntryPoint, Fee, TransactionHash, TransactionNonce, TransactionSignatureElem,
        TransactionVersion,
    };
    use pathfinder_serde::TransactionVersionAsHexStr;
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
        pub fn hash(&self) -> TransactionHash {
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
        pub hash: TransactionHash,
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
            use primitive_types::H256;
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
            use primitive_types::H256;
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
        pub hash: TransactionHash,
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
        pub hash: TransactionHash,
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
        pub hash: TransactionHash,
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
    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    // #[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
    #[serde(deny_unknown_fields)]
    pub struct FeeEstimate {
        /// The Ethereum gas cost of the transaction
        #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
        pub gas_consumed: primitive_types::U256,
        /// The gas price (in gwei) that was used in the cost estimation (input to fee estimation)
        #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
        pub gas_price: primitive_types::U256,
        /// The estimated fee for the transaction (in gwei), product of gas_consumed and gas_price
        #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
        pub overall_fee: primitive_types::U256,
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

            use pathfinder_common::macro_prelude::*;
            use pretty_assertions::assert_eq;

            #[test]
            fn transaction() {
                let transactions = vec![
                    Transaction::Declare(DeclareTransaction::V1(DeclareTransactionV0V1 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: transaction_hash!("0x4"),
                            max_fee: fee!("0x5"),
                            signature: vec![transaction_signature_elem!("0x7")],
                            nonce: transaction_nonce!("0x8"),
                        },
                        class_hash: class_hash!("0x9"),
                        sender_address: contract_address!("0xa"),
                    })),
                    Transaction::Declare(DeclareTransaction::V2(DeclareTransactionV2 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: transaction_hash!("0x44"),
                            max_fee: fee!("0x55"),
                            signature: vec![transaction_signature_elem!("0x77")],
                            nonce: transaction_nonce!("0x88"),
                        },
                        class_hash: class_hash!("0x90"),
                        sender_address: contract_address!("0xa0"),
                        compiled_class_hash: casm_hash!("0xb0"),
                    })),
                    Transaction::Invoke(InvokeTransaction::V0(InvokeTransactionV0 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: transaction_hash!("0xb"),
                            max_fee: fee!("0x999"),
                            signature: vec![transaction_signature_elem!("0x777")],
                            nonce: transaction_nonce!("0xdd"),
                        },
                        contract_address: contract_address!("0xb"),
                        entry_point_selector: entry_point!("0xc"),
                        calldata: vec![call_param!("0xd")],
                    })),
                    Transaction::Invoke(InvokeTransaction::V1(InvokeTransactionV1 {
                        common: CommonDeclareInvokeTransactionProperties {
                            hash: transaction_hash!("0xbbb"),
                            max_fee: fee!("0x9999"),
                            signature: vec![transaction_signature_elem!("0xeee")],
                            nonce: transaction_nonce!("0xde"),
                        },
                        sender_address: contract_address!("0xc"),
                        calldata: vec![call_param!("0xddd")],
                    })),
                    Transaction::Deploy(DeployTransaction {
                        hash: transaction_hash!("0xe"),
                        class_hash: class_hash!("0x10"),
                        version: TransactionVersion(primitive_types::H256::from_low_u64_be(1)),
                        contract_address_salt: contract_address_salt!("0xee"),
                        constructor_calldata: vec![constructor_param!("0x11")],
                    }),
                    Transaction::L1Handler(L1HandlerTransaction {
                        hash: transaction_hash!("0xf"),
                        version: TransactionVersion(primitive_types::H256::from_low_u64_be(1)),
                        nonce: transaction_nonce!("0x8"),
                        contract_address: contract_address!("0xfff"),
                        entry_point_selector: entry_point!("0xf"),
                        calldata: vec![call_param!("0xf")],
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
