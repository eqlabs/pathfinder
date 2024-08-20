use pathfinder_common::{ContractAddress, TransactionHash};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::{KnownStarknetErrorCode, SequencerError};

use crate::context::RpcContext;
use crate::v02::types::request::{
    BroadcastedDeployAccountTransaction,
    BroadcastedDeployAccountTransactionV1,
};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "DEPLOY_ACCOUNT")]
    DeployAccount(BroadcastedDeployAccountTransaction),
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Input {
    deploy_account_transaction: Transaction,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    transaction_hash: TransactionHash,
    contract_address: ContractAddress,
}

#[derive(Debug)]
pub enum AddDeployAccountTransactionError {
    ClassHashNotFound,
    InvalidTransactionNonce,
    InsufficientMaxFee,
    InsufficientAccountBalance,
    ValidationFailure(String),
    DuplicateTransaction,
    NonAccount,
    UnsupportedTransactionVersion,
    UnexpectedError(String),
}

impl From<AddDeployAccountTransactionError> for crate::error::ApplicationError {
    fn from(value: AddDeployAccountTransactionError) -> Self {
        use AddDeployAccountTransactionError::*;
        match value {
            ClassHashNotFound => Self::ClassHashNotFound,
            InvalidTransactionNonce => Self::InvalidTransactionNonce,
            InsufficientMaxFee => Self::InsufficientMaxFee,
            InsufficientAccountBalance => Self::InsufficientAccountBalance,
            ValidationFailure(message) => Self::ValidationFailureV06(message),
            DuplicateTransaction => Self::DuplicateTransaction,
            NonAccount => Self::NonAccount,
            UnsupportedTransactionVersion => Self::UnsupportedTxVersion,
            UnexpectedError(data) => Self::UnexpectedError { data },
        }
    }
}

impl From<SequencerError> for AddDeployAccountTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::KnownStarknetErrorCode::{
            DuplicatedTransaction,
            EntryPointNotFound,
            InsufficientAccountBalance,
            InsufficientMaxFee,
            InvalidTransactionNonce,
            InvalidTransactionVersion,
            UndeclaredClass,
            ValidateFailure,
        };
        match e {
            SequencerError::StarknetError(e) if e.code == UndeclaredClass.into() => {
                AddDeployAccountTransactionError::ClassHashNotFound
            }
            SequencerError::StarknetError(e) if e.code == DuplicatedTransaction.into() => {
                AddDeployAccountTransactionError::DuplicateTransaction
            }
            SequencerError::StarknetError(e) if e.code == InsufficientAccountBalance.into() => {
                AddDeployAccountTransactionError::InsufficientAccountBalance
            }
            SequencerError::StarknetError(e) if e.code == InsufficientMaxFee.into() => {
                AddDeployAccountTransactionError::InsufficientMaxFee
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionNonce.into() => {
                AddDeployAccountTransactionError::InvalidTransactionNonce
            }
            SequencerError::StarknetError(e) if e.code == ValidateFailure.into() => {
                AddDeployAccountTransactionError::ValidationFailure(e.message)
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionVersion.into() => {
                AddDeployAccountTransactionError::UnsupportedTransactionVersion
            }
            SequencerError::StarknetError(e) if e.code == EntryPointNotFound.into() => {
                AddDeployAccountTransactionError::NonAccount
            }
            _ => AddDeployAccountTransactionError::UnexpectedError(e.to_string()),
        }
    }
}

pub async fn add_deploy_account_transaction(
    context: RpcContext,
    input: Input,
) -> Result<Output, AddDeployAccountTransactionError> {
    let contract_address = match &input.deploy_account_transaction {
        Transaction::DeployAccount(tx) => tx.deployed_contract_address(),
    };
    let Transaction::DeployAccount(tx) = input.deploy_account_transaction;
    let response = add_deploy_account_transaction_impl(&context, tx).await?;

    Ok(Output {
        transaction_hash: response.transaction_hash,
        contract_address,
    })
}

pub(crate) async fn add_deploy_account_transaction_impl(
    context: &RpcContext,
    tx: BroadcastedDeployAccountTransaction,
) -> Result<starknet_gateway_types::reply::add_transaction::DeployAccountResponse, SequencerError> {
    use starknet_gateway_types::request::add_transaction;

    match tx {
        BroadcastedDeployAccountTransaction::V1(
            tx @ BroadcastedDeployAccountTransactionV1 { version, .. },
        ) if version.without_query_version() == 0 => {
            context
                .sequencer
                .add_deploy_account(add_transaction::DeployAccount::V0(
                    add_transaction::DeployAccountV0V1 {
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        nonce: tx.nonce,
                        class_hash: tx.class_hash,
                        contract_address_salt: tx.contract_address_salt,
                        constructor_calldata: tx.constructor_calldata,
                    },
                ))
                .await
        }
        BroadcastedDeployAccountTransaction::V1(
            tx @ BroadcastedDeployAccountTransactionV1 { version, .. },
        ) if version.without_query_version() == 1 => {
            context
                .sequencer
                .add_deploy_account(add_transaction::DeployAccount::V1(
                    add_transaction::DeployAccountV0V1 {
                        max_fee: tx.max_fee,
                        signature: tx.signature,
                        nonce: tx.nonce,
                        class_hash: tx.class_hash,
                        contract_address_salt: tx.contract_address_salt,
                        constructor_calldata: tx.constructor_calldata,
                    },
                ))
                .await
        }
        BroadcastedDeployAccountTransaction::V1(_) => Err(SequencerError::StarknetError(
            starknet_gateway_types::error::StarknetError {
                code: KnownStarknetErrorCode::InvalidTransactionVersion.into(),
                message: "".to_string(),
            },
        )),
        BroadcastedDeployAccountTransaction::V3(tx) => {
            context
                .sequencer
                .add_deploy_account(add_transaction::DeployAccount::V3(
                    add_transaction::DeployAccountV3 {
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
                        class_hash: tx.class_hash,
                        contract_address_salt: tx.contract_address_salt,
                        constructor_calldata: tx.constructor_calldata,
                    },
                ))
                .await
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
        serializer.serialize_field(
            "contract_address",
            &crate::dto::Felt(&self.contract_address.0),
        )?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        ResourceAmount,
        ResourcePricePerUnit,
        Tip,
        TransactionNonce,
        TransactionVersion,
    };

    use super::*;
    use crate::v02::types::request::BroadcastedDeployAccountTransactionV3;
    use crate::v02::types::{DataAvailabilityMode, ResourceBound, ResourceBounds};

    const INPUT_JSON: &str = r#"{
        "max_fee": "0xbf391377813",
        "version": "0x1",
        "constructor_calldata": [
            "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
        ],
        "signature": [
            "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
            "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
        ],
        "nonce": "0x0",
        "class_hash": "01fac3074c9d5282f0acc5c69a4781a1c711efea5e73c550c5d9fb253cf7fd3d",
        "contract_address_salt": "06d44a6aecb4339e23a9619355f101cf3cb9baec289fcd9fd51486655c1bb8a8",
        "type": "DEPLOY_ACCOUNT"
    }"#;

    #[tokio::test]
    async fn test_parse_input_named() {
        let json = format!("{{\"deploy_account_transaction\":{INPUT_JSON}}}");
        let input: Input = serde_json::from_str(&json).expect("parse named input");

        assert_eq!(input, get_input());
    }

    #[tokio::test]
    async fn test_parse_input_positional() {
        let json = format!("[{INPUT_JSON}]");
        let input: Input = serde_json::from_str(&json).expect("parse positional input");

        assert_eq!(input, get_input());
    }

    #[test]
    fn unexpected_error_message() {
        use starknet_gateway_types::error::{
            KnownStarknetErrorCode,
            StarknetError,
            StarknetErrorCode,
        };
        let starknet_error = SequencerError::StarknetError(StarknetError {
            code: StarknetErrorCode::Known(KnownStarknetErrorCode::TransactionLimitExceeded),
            message: "StarkNet Alpha throughput limit reached, please wait a few minutes and try \
                      again."
                .to_string(),
        });

        let error = AddDeployAccountTransactionError::from(starknet_error);
        let error = crate::error::ApplicationError::from(error);
        let error = crate::jsonrpc::RpcError::from(error);
        let error = serde_json::to_value(error).unwrap();

        let expected = serde_json::json!({
            "code": 63,
            "message": "An unexpected error occurred",
            "data": "StarkNet Alpha throughput limit reached, please wait a few minutes and try again."
        });

        assert_eq!(error, expected);
    }

    fn get_input() -> Input {
        Input {
            deploy_account_transaction: Transaction::DeployAccount(
                BroadcastedDeployAccountTransaction::V1(BroadcastedDeployAccountTransactionV1 {
                    version: TransactionVersion::ONE,
                    max_fee: fee!("0xbf391377813"),
                    signature: vec![
                        transaction_signature_elem!(
                            "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                        ),
                        transaction_signature_elem!(
                            "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                        ),
                    ],
                    nonce: TransactionNonce::ZERO,

                    contract_address_salt: contract_address_salt!(
                        "06d44a6aecb4339e23a9619355f101cf3cb9baec289fcd9fd51486655c1bb8a8"
                    ),
                    constructor_calldata: vec![call_param!(
                        "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                    )],
                    class_hash: class_hash!(
                        "01fac3074c9d5282f0acc5c69a4781a1c711efea5e73c550c5d9fb253cf7fd3d"
                    ),
                }),
            ),
        }
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    async fn duplicate_transaction() {
        let context = RpcContext::for_tests();

        let input = get_input();

        let error = add_deploy_account_transaction(context, input)
            .await
            .expect_err("add_deploy_account_transaction");
        assert_matches::assert_matches!(
            error,
            AddDeployAccountTransactionError::DuplicateTransaction
        );
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    // https://external.integration.starknet.io/feeder_gateway/get_transaction?transactionHash=0x29fd7881f14380842414cdfdd8d6c0b1f2174f8916edcfeb1ede1eb26ac3ef0
    async fn duplicate_v3_transaction() {
        let context = RpcContext::for_tests_on(pathfinder_common::Chain::SepoliaIntegration);

        let input = BroadcastedDeployAccountTransactionV3 {
            version: TransactionVersion::THREE,
            signature: vec![
                transaction_signature_elem!(
                    "0x6d756e754793d828c6c1a89c13f7ec70dbd8837dfeea5028a673b80e0d6b4ec"
                ),
                transaction_signature_elem!(
                    "0x4daebba599f860daee8f6e100601d98873052e1c61530c630cc4375c6bd48e3"
                ),
            ],
            nonce: transaction_nonce!("0x0"),
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
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            contract_address_salt: contract_address_salt!("0x0"),
            constructor_calldata: vec![call_param!(
                "0x5cd65f3d7daea6c63939d659b8473ea0c5cd81576035a4d34e52fb06840196c"
            )],
            class_hash: class_hash!(
                "0x2338634f11772ea342365abd5be9d9dc8a6f44f159ad782fdebd3db5d969738"
            ),
        };

        let input = Input {
            deploy_account_transaction: Transaction::DeployAccount(
                BroadcastedDeployAccountTransaction::V3(input),
            ),
        };

        let error = add_deploy_account_transaction(context, input)
            .await
            .expect_err("add_deploy_account_transaction");
        assert_matches::assert_matches!(
            error,
            AddDeployAccountTransactionError::DuplicateTransaction
        );
    }
}
