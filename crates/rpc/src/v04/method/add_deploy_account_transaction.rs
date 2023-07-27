use crate::context::RpcContext;
use crate::felt::{RpcFelt, RpcFelt251};
use crate::v02::types::request::BroadcastedDeployAccountTransaction;
use pathfinder_common::{ContractAddress, TransactionHash};
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "DEPLOY_ACCOUNT")]
    DeployAccount(BroadcastedDeployAccountTransaction),
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq)]
pub struct AddDeployAccountTransactionInput {
    deploy_account_transaction: Transaction,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddDeployAccountTransactionOutput {
    #[serde_as(as = "RpcFelt")]
    transaction_hash: TransactionHash,
    #[serde_as(as = "RpcFelt251")]
    contract_address: ContractAddress,
}

#[derive(Debug)]
pub enum AddDeployAccountTransactionError {
    ClassHashNotFound,
    InvalidTransactionNonce,
    InsufficientMaxFee,
    InsufficientAccountBalance,
    ValidationFailure,
    DuplicateTransaction,
    NonAccount,
    UnsupportedTransactionVersion,
    UnexpectedError(String),
}

impl From<AddDeployAccountTransactionError> for crate::error::RpcError {
    fn from(value: AddDeployAccountTransactionError) -> Self {
        use AddDeployAccountTransactionError::*;
        match value {
            ClassHashNotFound => Self::ClassHashNotFound,
            InvalidTransactionNonce => Self::InvalidTransactionNonce,
            InsufficientMaxFee => Self::InsufficientMaxFee,
            InsufficientAccountBalance => Self::InsufficientAccountBalance,
            ValidationFailure => Self::ValidationFailure,
            DuplicateTransaction => Self::DuplicateTransaction,
            NonAccount => Self::NonAccount,
            UnsupportedTransactionVersion => Self::UnsupportedTxVersion,
            UnexpectedError(data) => Self::UnexpectedError { data },
        }
    }
}

impl From<anyhow::Error> for AddDeployAccountTransactionError {
    fn from(value: anyhow::Error) -> Self {
        AddDeployAccountTransactionError::UnexpectedError(value.to_string())
    }
}

impl From<SequencerError> for AddDeployAccountTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::KnownStarknetErrorCode::{
            DuplicatedTransaction, EntryPointNotFound, InsufficientAccountBalance,
            InsufficientMaxFee, InvalidTransactionNonce, InvalidTransactionVersion,
            UndeclaredClass, ValidateFailure,
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
                AddDeployAccountTransactionError::ValidationFailure
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
    input: AddDeployAccountTransactionInput,
) -> Result<AddDeployAccountTransactionOutput, AddDeployAccountTransactionError> {
    let Transaction::DeployAccount(tx) = input.deploy_account_transaction;
    let response = context
        .sequencer
        .add_deploy_account(
            tx.version,
            tx.max_fee,
            tx.signature,
            tx.nonce,
            tx.contract_address_salt,
            tx.class_hash,
            tx.constructor_calldata,
        )
        .await?;

    Ok(AddDeployAccountTransactionOutput {
        transaction_hash: response.transaction_hash,
        contract_address: response.address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{TransactionNonce, TransactionVersion};

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
        let input: AddDeployAccountTransactionInput =
            serde_json::from_str(&json).expect("parse named input");

        assert_eq!(input, get_input());
    }

    #[tokio::test]
    async fn test_parse_input_positional() {
        let json = format!("[{INPUT_JSON}]");
        let input: AddDeployAccountTransactionInput =
            serde_json::from_str(&json).expect("parse positional input");

        assert_eq!(input, get_input());
    }

    fn get_input() -> AddDeployAccountTransactionInput {
        AddDeployAccountTransactionInput {
            deploy_account_transaction: Transaction::DeployAccount(
                BroadcastedDeployAccountTransaction {
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
                },
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
}
