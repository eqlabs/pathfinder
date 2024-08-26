use pathfinder_common::{ClassHash, TransactionHash};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;
use starknet_gateway_types::request::add_transaction::{
    CairoContractDefinition,
    ContractDefinition,
    SierraContractDefinition,
};

use crate::context::RpcContext;
use crate::v02::types::request::BroadcastedDeclareTransaction;

#[derive(Debug)]
pub enum AddDeclareTransactionError {
    ClassAlreadyDeclared,
    InvalidTransactionNonce,
    InsufficientMaxFee,
    InsufficientAccountBalance,
    ValidationFailure(String),
    CompilationFailed,
    ContractClassSizeIsTooLarge,
    DuplicateTransaction,
    CompiledClassHashMismatch,
    NonAccount,
    UnsupportedTransactionVersion,
    UnsupportedContractClassVersion,
    UnexpectedError(String),
}

impl From<AddDeclareTransactionError> for crate::error::ApplicationError {
    fn from(value: AddDeclareTransactionError) -> Self {
        match value {
            AddDeclareTransactionError::ClassAlreadyDeclared => Self::ClassAlreadyDeclared,
            AddDeclareTransactionError::InvalidTransactionNonce => Self::InvalidTransactionNonce,
            AddDeclareTransactionError::InsufficientMaxFee => Self::InsufficientMaxFee,
            AddDeclareTransactionError::InsufficientAccountBalance => {
                Self::InsufficientAccountBalance
            }
            AddDeclareTransactionError::ValidationFailure(message) => {
                Self::ValidationFailureV06(message)
            }
            AddDeclareTransactionError::CompilationFailed => Self::CompilationFailed,
            AddDeclareTransactionError::ContractClassSizeIsTooLarge => {
                Self::ContractClassSizeIsTooLarge
            }
            AddDeclareTransactionError::DuplicateTransaction => Self::DuplicateTransaction,
            AddDeclareTransactionError::CompiledClassHashMismatch => {
                Self::CompiledClassHashMismatch
            }
            AddDeclareTransactionError::NonAccount => Self::NonAccount,
            AddDeclareTransactionError::UnsupportedTransactionVersion => Self::UnsupportedTxVersion,
            AddDeclareTransactionError::UnsupportedContractClassVersion => {
                Self::UnsupportedContractClassVersion
            }
            AddDeclareTransactionError::UnexpectedError(data) => Self::UnexpectedError { data },
        }
    }
}

impl From<anyhow::Error> for AddDeclareTransactionError {
    fn from(value: anyhow::Error) -> Self {
        AddDeclareTransactionError::UnexpectedError(value.to_string())
    }
}

impl From<SequencerError> for AddDeclareTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::KnownStarknetErrorCode::{
            ClassAlreadyDeclared,
            CompilationFailed,
            ContractBytecodeSizeTooLarge,
            ContractClassObjectSizeTooLarge,
            DuplicatedTransaction,
            EntryPointNotFound,
            InsufficientAccountBalance,
            InsufficientMaxFee,
            InvalidCompiledClassHash,
            InvalidContractClassVersion,
            InvalidTransactionNonce,
            InvalidTransactionVersion,
            ValidateFailure,
        };
        match e {
            SequencerError::StarknetError(e) if e.code == ClassAlreadyDeclared.into() => {
                AddDeclareTransactionError::ClassAlreadyDeclared
            }
            SequencerError::StarknetError(e) if e.code == CompilationFailed.into() => {
                AddDeclareTransactionError::CompilationFailed
            }
            SequencerError::StarknetError(e)
                if e.code == ContractBytecodeSizeTooLarge.into()
                    || e.code == ContractClassObjectSizeTooLarge.into() =>
            {
                AddDeclareTransactionError::ContractClassSizeIsTooLarge
            }
            SequencerError::StarknetError(e) if e.code == DuplicatedTransaction.into() => {
                AddDeclareTransactionError::DuplicateTransaction
            }
            SequencerError::StarknetError(e) if e.code == InsufficientAccountBalance.into() => {
                AddDeclareTransactionError::InsufficientAccountBalance
            }
            SequencerError::StarknetError(e) if e.code == InsufficientMaxFee.into() => {
                AddDeclareTransactionError::InsufficientMaxFee
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionNonce.into() => {
                AddDeclareTransactionError::InvalidTransactionNonce
            }
            SequencerError::StarknetError(e) if e.code == ValidateFailure.into() => {
                AddDeclareTransactionError::ValidationFailure(e.message)
            }
            SequencerError::StarknetError(e) if e.code == InvalidCompiledClassHash.into() => {
                AddDeclareTransactionError::CompiledClassHashMismatch
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionVersion.into() => {
                AddDeclareTransactionError::UnsupportedTransactionVersion
            }
            SequencerError::StarknetError(e) if e.code == InvalidContractClassVersion.into() => {
                AddDeclareTransactionError::UnsupportedContractClassVersion
            }
            SequencerError::StarknetError(e) if e.code == EntryPointNotFound.into() => {
                AddDeclareTransactionError::NonAccount
            }
            _ => AddDeclareTransactionError::UnexpectedError(e.to_string()),
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
#[serde(deny_unknown_fields)]
pub struct Input {
    declare_transaction: Transaction,
    // An undocumented parameter that we forward to the sequencer API
    // A deploy token is required to deploy contracts on Starknet mainnet only.
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    transaction_hash: TransactionHash,
    class_hash: ClassHash,
}

pub async fn add_declare_transaction(
    context: RpcContext,
    input: Input,
) -> Result<Output, AddDeclareTransactionError> {
    use starknet_gateway_types::request::add_transaction;

    match input.declare_transaction {
        Transaction::Declare(BroadcastedDeclareTransaction::V0(_)) => {
            Err(AddDeclareTransactionError::UnsupportedTransactionVersion)
        }
        Transaction::Declare(BroadcastedDeclareTransaction::V1(tx)) => {
            let contract_definition: CairoContractDefinition = tx
                .contract_class
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert contract definition: {}", e))?;

            let response = context
                .sequencer
                .add_declare_transaction(
                    add_transaction::Declare::V1(add_transaction::DeclareV0V1V2 {
                        version: tx.version,
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        contract_class: ContractDefinition::Cairo(contract_definition),
                        sender_address: tx.sender_address,
                        nonce: tx.nonce,
                        compiled_class_hash: None,
                    }),
                    input.token,
                )
                .await?;

            Ok(Output {
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
                    add_transaction::Declare::V2(add_transaction::DeclareV0V1V2 {
                        version: tx.version,
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        contract_class: ContractDefinition::Sierra(contract_definition),
                        sender_address: tx.sender_address,
                        nonce: tx.nonce,
                        compiled_class_hash: Some(tx.compiled_class_hash),
                    }),
                    input.token,
                )
                .await?;

            Ok(Output {
                transaction_hash: response.transaction_hash,
                class_hash: response.class_hash,
            })
        }
        Transaction::Declare(BroadcastedDeclareTransaction::V3(tx)) => {
            let contract_definition: SierraContractDefinition = tx
                .contract_class
                .try_into()
                .map_err(|e| anyhow::anyhow!("Failed to convert contract definition: {}", e))?;

            let response = context
                .sequencer
                .add_declare_transaction(
                    add_transaction::Declare::V3(add_transaction::DeclareV3 {
                        signature: tx.signature,
                        nonce: tx.nonce,
                        nonce_data_availability_mode:
                            pathfinder_common::transaction::DataAvailabilityMode::from(
                                tx.nonce_data_availability_mode,
                            )
                            .into(),
                        fee_data_availability_mode:
                            pathfinder_common::transaction::DataAvailabilityMode::from(
                                tx.fee_data_availability_mode,
                            )
                            .into(),
                        resource_bounds: pathfinder_common::transaction::ResourceBounds::from(
                            tx.resource_bounds,
                        )
                        .into(),
                        tip: tx.tip,
                        paymaster_data: tx.paymaster_data,
                        contract_class: contract_definition,
                        compiled_class_hash: tx.compiled_class_hash,
                        sender_address: tx.sender_address,
                        account_deployment_data: tx.account_deployment_data,
                    }),
                    input.token,
                )
                .await?;

            Ok(Output {
                transaction_hash: response.transaction_hash,
                class_hash: response.class_hash,
            })
        }
    }
}

impl crate::dto::serialize::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::serialize::Serializer,
    ) -> Result<crate::dto::serialize::Ok, crate::dto::serialize::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field(
            "transaction_hash",
            &crate::dto::Felt(&self.transaction_hash.0),
        )?;
        serializer.serialize_field("class_hash", &crate::dto::Felt(&self.class_hash.0))?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        CasmHash,
        ContractAddress,
        Fee,
        ResourceAmount,
        ResourcePricePerUnit,
        Tip,
        TransactionNonce,
        TransactionVersion,
    };
    use pathfinder_crypto::Felt;
    use starknet_gateway_test_fixtures::class_definitions::{
        CAIRO_2_0_0_STACK_OVERFLOW,
        CONTRACT_DEFINITION,
    };

    use super::*;
    use crate::v02::types::request::{
        BroadcastedDeclareTransaction,
        BroadcastedDeclareTransactionV1,
        BroadcastedDeclareTransactionV2,
        BroadcastedDeclareTransactionV3,
    };
    use crate::v02::types::{
        CairoContractClass,
        ContractClass,
        DataAvailabilityMode,
        ResourceBound,
        ResourceBounds,
        SierraContractClass,
    };

    pub static CONTRACT_CLASS: LazyLock<CairoContractClass> = LazyLock::new(|| {
        ContractClass::from_definition_bytes(CONTRACT_DEFINITION)
            .unwrap()
            .as_cairo()
            .unwrap()
    });

    pub static CONTRACT_CLASS_WITH_INVALID_PRIME: LazyLock<CairoContractClass> =
        LazyLock::new(|| {
            let mut definition: serde_json::Value =
                serde_json::from_slice(CONTRACT_DEFINITION).unwrap();
            // change program.prime to an invalid one
            *definition
                .get_mut("program")
                .unwrap()
                .get_mut("prime")
                .unwrap() = serde_json::json!("0x1");
            let definition = serde_json::to_vec(&definition).unwrap();
            ContractClass::from_definition_bytes(&definition)
                .unwrap()
                .as_cairo()
                .unwrap()
        });

    pub static SIERRA_CLASS: LazyLock<SierraContractClass> = LazyLock::new(|| {
        ContractClass::from_definition_bytes(CAIRO_2_0_0_STACK_OVERFLOW)
            .unwrap()
            .as_sierra()
            .unwrap()
    });

    pub static INTEGRATION_SIERRA_CLASS: LazyLock<SierraContractClass> = LazyLock::new(|| {
        ContractClass::from_definition_bytes(include_bytes!(
            "../../fixtures/contracts/\
             integration_class_0x5ae9d09292a50ed48c5930904c880dab56e85b825022a7d689cfc9e65e01ee7.\
             json"
        ))
        .unwrap()
        .as_sierra()
        .unwrap()
    });

    mod parsing {
        mod v1 {
            use serde_json::json;

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
                let positional = json!([{
                    "type": "DECLARE",
                    "version": "0x1",
                    "max_fee": "0x1",
                    "signature": [],
                    "nonce": "0x0",
                    "contract_class": CONTRACT_CLASS.clone(),
                    "sender_address": "0x1"
                }]);
                let input = serde_json::from_value::<Input>(positional).unwrap();
                let expected = Input {
                    declare_transaction: test_declare_txn(),
                    token: None,
                };
                assert_eq!(input, expected);
            }

            #[test]
            fn named_args() {
                let named = json!({
                    "declare_transaction": {
                        "type": "DECLARE",
                        "version": "0x1",
                        "max_fee": "0x1",
                        "signature": [],
                        "nonce": "0x0",
                        "contract_class": CONTRACT_CLASS.clone(),
                        "sender_address": "0x1"
                    },
                    "token": "token"
                });
                let input = serde_json::from_value::<Input>(named).unwrap();
                let expected = Input {
                    declare_transaction: test_declare_txn(),
                    token: Some("token".to_owned()),
                };
                assert_eq!(input, expected);
            }

            #[test]
            fn unexpected_error_message() {
                use starknet_gateway_types::error::{
                    KnownStarknetErrorCode,
                    StarknetError,
                    StarknetErrorCode,
                };
                let starknet_error = SequencerError::StarknetError(StarknetError {
                    code: StarknetErrorCode::Known(
                        KnownStarknetErrorCode::TransactionLimitExceeded,
                    ),
                    message: "StarkNet Alpha throughput limit reached, please wait a few minutes \
                              and try again."
                        .to_string(),
                });

                let error = AddDeclareTransactionError::from(starknet_error);
                let error = crate::error::ApplicationError::from(error);
                let error = crate::jsonrpc::RpcError::from(error);
                let error = serde_json::to_value(error).unwrap();

                let expected = json!({
                    "code": 63,
                    "message": "An unexpected error occurred",
                    "data": "StarkNet Alpha throughput limit reached, please wait a few minutes and try again."
                });

                assert_eq!(error, expected);
            }
        }

        mod v2 {
            use serde_json::json;

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
                let positional = json!([{
                    "type": "DECLARE",
                    "version": "0x2",
                    "max_fee": "0x1",
                    "signature": [],
                    "nonce": "0x0",
                    "contract_class": SIERRA_CLASS.clone(),
                    "sender_address": "0x1",
                    "compiled_class_hash": "0x1"
                }]);

                let input = serde_json::from_value::<Input>(positional).unwrap();
                let expected = Input {
                    declare_transaction: test_declare_txn(),
                    token: None,
                };
                pretty_assertions_sorted::assert_eq!(input, expected);
            }

            #[test]
            fn named_args() {
                let named = json!({
                    "declare_transaction": {
                        "type": "DECLARE",
                        "version": "0x2",
                        "max_fee": "0x1",
                        "signature": [],
                        "nonce": "0x0",
                        "contract_class": SIERRA_CLASS.clone(),
                        "sender_address": "0x1",
                        "compiled_class_hash": "0x1"
                    },
                    "token": "token"
                });

                let input = serde_json::from_value::<Input>(named).unwrap();
                let expected = Input {
                    declare_transaction: test_declare_txn(),
                    token: Some("token".to_owned()),
                };
                pretty_assertions_sorted::assert_eq!(input, expected);
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

        let input = Input {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::UnexpectedError(_));
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn invalid_contract_definition_v2() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::SepoliaIntegration);

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

        let input = Input {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::UnexpectedError(_));
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

        let input = Input {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::UnexpectedError(_));
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn duplicate_transaction() {
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

        let input = Input {
            declare_transaction,
            token: None,
        };
        let error = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddDeclareTransactionError::DuplicateTransaction);
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn insufficient_max_fee() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::SepoliaIntegration);

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(felt!("0x01")),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: SIERRA_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                compiled_class_hash: casm_hash!(
                    "0x688e44b1d8612222a25cf742c8e1493af4640fa74b1a7707bde2002df51ea8c"
                ),
            },
        ));

        let input = Input {
            declare_transaction,
            token: None,
        };
        let err = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(
            err,
            AddDeclareTransactionError::InsufficientAccountBalance
        );
    }

    #[test_log::test(tokio::test)]
    #[ignore = "gateway 429"]
    async fn insufficient_account_balance() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::SepoliaIntegration);

        let declare_transaction = Transaction::Declare(BroadcastedDeclareTransaction::V2(
            BroadcastedDeclareTransactionV2 {
                version: TransactionVersion::TWO,
                max_fee: Fee(Felt::from_be_slice(&u64::MAX.to_be_bytes()).unwrap()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                contract_class: SIERRA_CLASS.clone(),
                sender_address: ContractAddress::new_or_panic(Felt::from_u64(1)),
                compiled_class_hash: casm_hash!(
                    "0x688e44b1d8612222a25cf742c8e1493af4640fa74b1a7707bde2002df51ea8c"
                ),
            },
        ));

        let input = Input {
            declare_transaction,
            token: None,
        };
        let err = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(
            err,
            AddDeclareTransactionError::InsufficientAccountBalance
        );
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    // https://external.integration.starknet.io/feeder_gateway/get_transaction?transactionHash=0x41d1f5206ef58a443e7d3d1ca073171ec25fa75313394318fc83a074a6631c3
    async fn duplicate_v3_transaction() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::SepoliaIntegration);

        let input = BroadcastedDeclareTransactionV3 {
            version: TransactionVersion::THREE,
            signature: vec![
                transaction_signature_elem!(
                    "0x29a49dff154fede73dd7b5ca5a0beadf40b4b069f3a850cd8428e54dc809ccc"
                ),
                transaction_signature_elem!(
                    "0x429d142a17223b4f2acde0f5ecb9ad453e188b245003c86fab5c109bad58fc3"
                ),
            ],
            nonce: transaction_nonce!("0x1"),
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(0x186a0),
                    max_price_per_unit: ResourcePricePerUnit(0x5af3107a4000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(0),
                    max_price_per_unit: ResourcePricePerUnit(0),
                },
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            compiled_class_hash: casm_hash!(
                "0x1add56d64bebf8140f3b8a38bdf102b7874437f0c861ab4ca7526ec33b4d0f8"
            ),
            contract_class: INTEGRATION_SIERRA_CLASS.clone(),
            sender_address: contract_address!(
                "0x2fab82e4aef1d8664874e1f194951856d48463c3e6bf9a8c68e234a629a6f50"
            ),
        };

        let input = Input {
            declare_transaction: Transaction::Declare(BroadcastedDeclareTransaction::V3(input)),
            token: None,
        };

        let err = add_declare_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(
            err,
            AddDeclareTransactionError::InsufficientAccountBalance
        );
    }
}
