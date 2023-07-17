use crate::context::RpcContext;
use crate::felt::RpcFelt;
use crate::v02::types::request::BroadcastedDeclareTransaction;
use pathfinder_common::{ClassHash, TransactionHash};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::{SequencerError, StarknetError};
use starknet_gateway_types::request::add_transaction::{
    CairoContractDefinition, ContractDefinition, SierraContractDefinition,
};

#[derive(Debug)]
pub enum AddDeclareTransactionError {
    InvalidContractClass,
    GatewayError(StarknetError),
    Internal(anyhow::Error),
}

impl From<AddDeclareTransactionError> for crate::error::RpcError {
    fn from(value: AddDeclareTransactionError) -> Self {
        match value {
            AddDeclareTransactionError::InvalidContractClass => Self::InvalidContractClass,
            AddDeclareTransactionError::GatewayError(x) => Self::GatewayError(x),
            AddDeclareTransactionError::Internal(x) => Self::Internal(x),
        }
    }
}

impl From<anyhow::Error> for AddDeclareTransactionError {
    fn from(value: anyhow::Error) -> Self {
        AddDeclareTransactionError::Internal(value)
    }
}

impl From<SequencerError> for AddDeclareTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::KnownStarknetErrorCode::{
            InvalidContractClass, InvalidProgram,
        };
        match e {
            SequencerError::StarknetError(e)
                if e.code == InvalidProgram.into() || e.code == InvalidContractClass.into() =>
            {
                AddDeclareTransactionError::InvalidContractClass
            }
            SequencerError::StarknetError(other) => AddDeclareTransactionError::GatewayError(other),
            _ => AddDeclareTransactionError::Internal(e.into()),
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
    transaction_hash: TransactionHash,
    #[serde_as(as = "RpcFelt")]
    class_hash: ClassHash,
}

pub async fn add_declare_transaction(
    context: RpcContext,
    input: AddDeclareTransactionInput,
) -> Result<AddDeclareTransactionOutput, AddDeclareTransactionError> {
    match input.declare_transaction {
        Transaction::Declare(BroadcastedDeclareTransaction::V1(tx)) => {
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
        BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV1,
        BroadcastedDeclareTransactionV2,
    };
    use crate::v02::types::{CairoContractClass, ContractClass, SierraContractClass};
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{CasmHash, ContractAddress, Fee, TransactionNonce, TransactionVersion};
    use stark_hash::Felt;
    use starknet_gateway_test_fixtures::class_definitions::{
        CAIRO_1_0_0_ALPHA6_SIERRA, CONTRACT_DEFINITION,
    };
    use starknet_gateway_types::error::KnownStarknetErrorCode;

    lazy_static::lazy_static! {
        pub static ref CONTRACT_CLASS: CairoContractClass = {
            ContractClass::from_definition_bytes(CONTRACT_DEFINITION).unwrap().as_cairo().unwrap()
        };

        pub static ref CONTRACT_CLASS_WITH_INVALID_PRIME: CairoContractClass = {
            let mut definition: serde_json::Value = serde_json::from_slice(CONTRACT_DEFINITION).unwrap();
            // change program.prime to an invalid one
            *definition.get_mut("program").unwrap().get_mut("prime").unwrap() = serde_json::json!("0x1");
            let definition = serde_json::to_vec(&definition).unwrap();
            ContractClass::from_definition_bytes(&definition).unwrap().as_cairo().unwrap()
        };

        pub static ref CONTRACT_CLASS_JSON: String = {
            serde_json::to_string(&*CONTRACT_CLASS).unwrap()
        };

        pub static ref SIERRA_CLASS_JSON: String = {
            serde_json::to_string(&*SIERRA_CLASS).unwrap()
        };

        pub static ref SIERRA_CLASS: SierraContractClass = {
            ContractClass::from_definition_bytes(CAIRO_1_0_0_ALPHA6_SIERRA).unwrap().as_sierra().unwrap()
        };
    }

    mod parsing {
        mod v1 {
            use super::super::*;
            use crate::v02::types::request::BroadcastedDeclareTransactionV1;

            fn test_declare_txn() -> Transaction {
                Transaction::Declare(BroadcastedDeclareTransaction::V1(
                    BroadcastedDeclareTransactionV1 {
                        max_fee: fee!("0x1"),
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
                        max_fee: fee!("0x1"),
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
    async fn invalid_contract_definition_v1() {
        let context = RpcContext::for_tests();

        let invalid_contract_class = CairoContractClass {
            program: "".to_owned(),
            ..CONTRACT_CLASS.clone()
        };

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
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
    #[ignore = "gateway 429"]
    async fn invalid_contract_definition_v2() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let invalid_contract_class = SierraContractClass {
            sierra_program: vec![],
            ..SIERRA_CLASS.clone()
        };

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: invalid_contract_class,
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                // Taken from
                // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=283364
                compiled_class_hash: casm_hash!(
                    "0x711c0c3e56863e29d3158804aac47f424241eda64db33e2cc2999d60ee5105"
                ),
            },
        ));

        let input = AddDeclareTransactionInput {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        // FIXME at least make sure a proper starknet error variant is returned from the gateway
        // until a more meaningful rpc error code is introduced in the spec and we can use it
        assert_matches::assert_matches!(error, AddDeclareTransactionError::Internal(error) => {
            let error = error.downcast::<SequencerError>().unwrap();
            assert_matches::assert_matches!(error, SequencerError::StarknetError(error) => {
                assert_eq!(error.code, KnownStarknetErrorCode::CompilationFailed.into());
            })
        });
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn invalid_contract_class() {
        let context = RpcContext::for_tests();

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE,
                max_fee: fee!("0xfffffffffff"),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: CONTRACT_CLASS_WITH_INVALID_PRIME.clone(),
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
    #[ignore = "gateway 429"]
    async fn successful_declare_v1() {
        let context = RpcContext::for_tests();

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V1(
            BroadcastedDeclareTransactionV1 {
                version: TransactionVersion::ONE,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
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
                transaction_hash: transaction_hash!(
                    "0xE32B5DC53B104DCC8487F8721A9AE26D038C5C667F83A15FD00E4BB87C4A6E"
                ),
                class_hash: class_hash!(
                    "0x50b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
                ),
            }
        );
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn successful_declare_v2() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::Integration);

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: SIERRA_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                // Taken from
                // https://external.integration.starknet.io/feeder_gateway/get_state_update?blockNumber=284544
                compiled_class_hash: casm_hash!(
                    "0x5bcd45099caf3dca6c0c0f6697698c90eebf02851acbbaf911186b173472fcc"
                ),
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
                transaction_hash: transaction_hash!(
                    "0x069B1F490F1E28458E7A22DBA1DE950F060036FAAE533592E2D5546A6347C892"
                ),
                class_hash: class_hash!(
                    "0x04D7D2DDF396736D7CDBA26E178E30E3388D488984A94E03BC4AF4841E222920"
                ),
            }
        );
    }
}
