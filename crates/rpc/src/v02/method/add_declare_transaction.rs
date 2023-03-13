use crate::felt::RpcFelt;
use crate::v02::types::request::BroadcastedDeclareTransaction;
use crate::v02::RpcContext;
use pathfinder_common::{ClassHash, StarknetTransactionHash};
use starknet_gateway_client::ClientApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::request::add_transaction::{
    CairoContractDefinition, ContractDefinition, SierraContractDefinition,
};

crate::error::generate_rpc_error_subset!(AddDeclareTransactionError: InvalidContractClass);

impl From<SequencerError> for AddDeclareTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::StarknetErrorCode::InvalidProgram;
        match e {
            SequencerError::StarknetError(e) if e.code == InvalidProgram => {
                Self::InvalidContractClass
            }
            _ => Self::Internal(e.into()),
        }
    }
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "DECLARE")]
    Declare(BroadcastedDeclareTransaction),
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct AddDeclareTransactionInput {
    declare_transaction: Transaction,
    // An undocumented parameter that we forward to the sequencer API
    // A deploy token is required to deploy contracts on Starknet mainnet only.
    #[serde(default)]
    token: Option<String>,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddDeclareTransactionOutput {
    #[serde_as(as = "RpcFelt")]
    transaction_hash: StarknetTransactionHash,
    #[serde_as(as = "RpcFelt")]
    class_hash: ClassHash,
}

pub async fn add_declare_transaction(
    context: RpcContext,
    input: AddDeclareTransactionInput,
) -> Result<AddDeclareTransactionOutput, AddDeclareTransactionError> {
    match input.declare_transaction {
        Transaction::Declare(BroadcastedDeclareTransaction::V0V1(tx)) => {
            let contract_definition: CairoContractDefinition = tx
                .contract_class
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert contract definition: {}", e))?;

            let response = context
                .sequencer
                .add_declare_transaction(
                    tx.version,
                    tx.max_fee,
                    tx.signature,
                    tx.nonce,
                    ContractDefinition::Cairo(contract_definition),
                    tx.sender_address,
                    None,
                    input.token,
                )
                .await?;

            Ok(AddDeclareTransactionOutput {
                transaction_hash: response.transaction_hash,
                class_hash: response.class_hash,
            })
        }
        Transaction::Declare(BroadcastedDeclareTransaction::V2(tx)) => {
            let contract_definition: SierraContractDefinition = tx
                .contract_class
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert contract definition: {}", e))?;

            let response = context
                .sequencer
                .add_declare_transaction(
                    tx.version,
                    tx.max_fee,
                    tx.signature,
                    tx.nonce,
                    ContractDefinition::Sierra(contract_definition),
                    tx.sender_address,
                    Some(tx.compiled_class_hash),
                    input.token,
                )
                .await?;

            Ok(AddDeclareTransactionOutput {
                transaction_hash: response.transaction_hash,
                class_hash: response.class_hash,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV0V1,
        BroadcastedDeclareTransactionV2,
    };
    use crate::v02::types::{CairoContractClass, ContractClass, SierraContractClass};
    use pathfinder_common::{
        felt, CasmHash, ContractAddress, Fee, TransactionNonce, TransactionVersion,
    };
    use stark_hash::Felt;

    lazy_static::lazy_static! {
        pub static ref CONTRACT_DEFINITION_JSON: Vec<u8> = {
            zstd::decode_all(starknet_gateway_test_fixtures::zstd_compressed_contracts::CONTRACT_DEFINITION).unwrap()
        };

        pub static ref CONTRACT_CLASS: CairoContractClass = {
            ContractClass::from_definition_bytes(&CONTRACT_DEFINITION_JSON).unwrap().as_cairo().unwrap()
        };

        pub static ref CONTRACT_CLASS_JSON: String = {
            serde_json::to_string(&*CONTRACT_CLASS).unwrap()
        };

        pub static ref SIERRA_CLASS_DEFINITION_JSON: Vec<u8> = {
            zstd::decode_all(starknet_gateway_test_fixtures::zstd_compressed_contracts::CAIRO_0_11_SIERRA).unwrap()
        };

        pub static ref SIERRA_CLASS_JSON: String = {
            serde_json::to_string(&*SIERRA_CLASS).unwrap()
        };

        pub static ref SIERRA_CLASS: SierraContractClass = {
            ContractClass::from_definition_bytes(&SIERRA_CLASS_DEFINITION_JSON).unwrap().as_sierra().unwrap()
        };
    }

    mod parsing {
        mod v1 {
            use super::super::*;
            use crate::v02::types::request::BroadcastedDeclareTransactionV0V1;

            fn test_declare_txn() -> Transaction {
                Transaction::Declare(BroadcastedDeclareTransaction::V0V1(
                    BroadcastedDeclareTransactionV0V1 {
                        max_fee: Fee(ethers::types::H128::from_low_u64_be(1)),
                        version: TransactionVersion::ONE,
                        signature: vec![],
                        nonce: TransactionNonce(Felt::ZERO),
                        contract_class: CONTRACT_CLASS.clone(),
                        sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                    },
                ))
            }

            #[test]
            fn positional_args() {
                use jsonrpsee::types::Params;

                let positional = format!(
                    r#"[
                        {{
                            "type": "DECLARE",
                            "version": "0x1",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1"
                        }}
                    ]"#,
                    CONTRACT_CLASS_JSON.clone()
                );
                let positional = Params::new(Some(&positional));

                let input = positional.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: None,
                };
                assert_eq!(input, expected);
            }

            #[test]
            fn named_args() {
                use jsonrpsee::types::Params;

                let named = format!(
                    r#"{{
                        "declare_transaction": {{
                            "type": "DECLARE",
                            "version": "0x1",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1"
                        }},
                        "token": "token"
                    }}"#,
                    CONTRACT_CLASS_JSON.clone()
                );
                let named = Params::new(Some(&named));

                let input = named.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: Some("token".to_owned()),
                };
                assert_eq!(input, expected);
            }
        }

        mod v2 {
            use super::super::*;
            use crate::v02::types::request::BroadcastedDeclareTransactionV2;

            fn test_declare_txn() -> Transaction {
                Transaction::Declare(BroadcastedDeclareTransaction::V2(
                    BroadcastedDeclareTransactionV2 {
                        max_fee: Fee(ethers::types::H128::from_low_u64_be(1)),
                        version: TransactionVersion::TWO,
                        signature: vec![],
                        nonce: TransactionNonce(Felt::ZERO),
                        contract_class: SIERRA_CLASS.clone(),
                        sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                        compiled_class_hash: CasmHash(Felt::from_u64(1)),
                    },
                ))
            }

            #[test]
            fn positional_args() {
                use jsonrpsee::types::Params;

                let positional = format!(
                    r#"[
                        {{
                            "type": "DECLARE",
                            "version": "0x2",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1",
                            "compiled_class_hash": "0x1"
                        }}
                    ]"#,
                    SIERRA_CLASS_JSON.clone()
                );
                let positional = Params::new(Some(&positional));

                let input = positional.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: None,
                };
                pretty_assertions::assert_eq!(input, expected);
            }

            #[test]
            fn named_args() {
                use jsonrpsee::types::Params;

                let named = format!(
                    r#"{{
                        "declare_transaction": {{
                            "type": "DECLARE",
                            "version": "0x2",
                            "max_fee": "0x1",
                            "signature": [],
                            "nonce": "0x0",
                            "contract_class": {},
                            "sender_address": "0x1",
                            "compiled_class_hash": "0x1"
                        }},
                        "token": "token"
                    }}"#,
                    SIERRA_CLASS_JSON.clone()
                );
                let named = Params::new(Some(&named));

                let input = named.parse::<AddDeclareTransactionInput>().unwrap();
                let expected = AddDeclareTransactionInput {
                    declare_transaction: test_declare_txn(),
                    token: Some("token".to_owned()),
                };
                pretty_assertions::assert_eq!(input, expected);
            }
        }
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn invalid_contract_definition() {
        let context = RpcContext::for_tests();

        let invalid_contract_class = CairoContractClass {
            program: "".to_owned(),
            ..CONTRACT_CLASS.clone()
        };

        // Fixme v0.11.0 only allow v2?
        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V0V1(
            BroadcastedDeclareTransactionV0V1 {
                version: TransactionVersion::ONE,
                max_fee: Fee(Default::default()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: invalid_contract_class,
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::InvalidContractClass);
    }

    #[test_log::test(tokio::test)]
    async fn invalid_contract_definition_v2() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let invalid_contract_class = SierraContractClass {
            sierra_program: vec![],
            ..SIERRA_CLASS.clone()
        };

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(ethers::types::H128::from_low_u64_be(u64::MAX)),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: invalid_contract_class,
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                // Taken from
                // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=283364
                compiled_class_hash: CasmHash::new_or_panic(felt!(
                    "0x711c0c3e56863e29d3158804aac47f424241eda64db33e2cc2999d60ee5105"
                )),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        // FIXME This should be a specific Starknet gateway variant, once the gateway is fixed
        assert_matches::assert_matches!(error, AddDeclareTransactionError::Internal(_));
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn successful_declare_v1() {
        let context = RpcContext::for_tests();

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V0V1(
            BroadcastedDeclareTransactionV0V1 {
                version: TransactionVersion::ONE,
                max_fee: Fee(Default::default()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: CONTRACT_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let result = add_declare_transaction(context, input).await.unwrap();
        assert_eq!(
            result,
            AddDeclareTransactionOutput {
                transaction_hash: StarknetTransactionHash(felt!(
                    "04b3791d16301be48268bfe1c0da7a9ad458847fd4666c98057d3940ef31775d"
                )),
                class_hash: ClassHash(felt!(
                    "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
                )),
            }
        );
    }

    #[test_log::test(tokio::test)]
    async fn successful_declare_v2() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(ethers::types::H128::from_low_u64_be(u64::MAX)),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: SIERRA_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                // Taken from
                // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=283364
                compiled_class_hash: CasmHash::new_or_panic(felt!(
                    "0x711c0c3e56863e29d3158804aac47f424241eda64db33e2cc2999d60ee5105"
                )),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let result = add_declare_transaction(context, input).await.unwrap();
        assert_eq!(
            result,
            AddDeclareTransactionOutput {
                transaction_hash: StarknetTransactionHash(felt!(
                    "0x076F6CF360512D1D33CF8AC32B9800480F5DA03DC680496874195B2B5B2A465E"
                )),
                class_hash: ClassHash(felt!(
                    "0x04E70B19333AE94BD958625F7B61CE9EEC631653597E68645E13780061B2136C"
                )),
            }
        );
    }
}
