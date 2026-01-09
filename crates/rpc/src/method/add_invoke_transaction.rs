use pathfinder_common::transaction::{
    InvokeTransactionV0,
    InvokeTransactionV1,
    InvokeTransactionV3,
    TransactionVariant,
};
use pathfinder_common::TransactionHash;
use serde::de::Error;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::SequencerError;

use crate::context::RpcContext;
use crate::types::request::BroadcastedInvokeTransaction;

#[derive(Debug, PartialEq, Eq)]
pub enum Transaction {
    Invoke(BroadcastedInvokeTransaction),
}

impl crate::dto::DeserializeForVersion for Transaction {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            let tag: String = value.deserialize("type")?;
            if tag != "INVOKE" {
                return Err(serde_json::Error::custom("Invalid transaction type"));
            }
            BroadcastedInvokeTransaction::deserialize(value).map(Self::Invoke)
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Input {
    invoke_transaction: Transaction,
}

impl Input {
    pub fn is_v3_transaction(&self) -> bool {
        matches!(
            self.invoke_transaction,
            Transaction::Invoke(BroadcastedInvokeTransaction::V3(_))
        )
    }
}

#[cfg(test)]
impl Input {
    pub(crate) fn for_test_with_v0_transaction() -> Self {
        Self {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V0(
                crate::types::request::BroadcastedInvokeTransactionV0 {
                    version: pathfinder_common::TransactionVersion::ZERO,
                    max_fee: Default::default(),
                    signature: Default::default(),
                    contract_address: Default::default(),
                    entry_point_selector: Default::default(),
                    calldata: Default::default(),
                },
            )),
        }
    }

    pub(crate) fn for_test_with_v1_transaction() -> Self {
        Self {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V1(
                crate::types::request::BroadcastedInvokeTransactionV1 {
                    version: pathfinder_common::TransactionVersion::ONE,
                    max_fee: Default::default(),
                    signature: Default::default(),
                    nonce: Default::default(),
                    sender_address: Default::default(),
                    calldata: Default::default(),
                },
            )),
        }
    }

    pub(crate) fn for_test_with_v3_transaction() -> Self {
        Self {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V3(
                crate::types::request::BroadcastedInvokeTransactionV3 {
                    version: pathfinder_common::TransactionVersion::THREE,
                    signature: Default::default(),
                    nonce: Default::default(),
                    resource_bounds: Default::default(),
                    tip: Default::default(),
                    paymaster_data: Default::default(),
                    account_deployment_data: Default::default(),
                    nonce_data_availability_mode: Default::default(),
                    fee_data_availability_mode: Default::default(),
                    sender_address: Default::default(),
                    calldata: Default::default(),
                    proof_facts: Default::default(),
                },
            )),
        }
    }
}

impl crate::dto::DeserializeForVersion for Input {
    fn deserialize(value: crate::dto::Value) -> Result<Self, serde_json::Error> {
        value.deserialize_map(|value| {
            Ok(Self {
                invoke_transaction: value.deserialize("invoke_transaction")?,
            })
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    transaction_hash: TransactionHash,
}

#[derive(Debug)]
pub enum AddInvokeTransactionError {
    InvalidTransactionNonce(String),
    InsufficientResourcesForValidate,
    InsufficientAccountBalance,
    ValidationFailure(String),
    DuplicateTransaction,
    NonAccount,
    UnsupportedTransactionVersion,
    UnexpectedError(String),
}

impl From<anyhow::Error> for AddInvokeTransactionError {
    fn from(e: anyhow::Error) -> Self {
        AddInvokeTransactionError::UnexpectedError(e.to_string())
    }
}

impl From<AddInvokeTransactionError> for crate::error::ApplicationError {
    fn from(value: AddInvokeTransactionError) -> Self {
        match value {
            AddInvokeTransactionError::InvalidTransactionNonce(data) => {
                Self::InvalidTransactionNonce { data }
            }
            AddInvokeTransactionError::InsufficientResourcesForValidate => {
                Self::InsufficientResourcesForValidate
            }
            AddInvokeTransactionError::InsufficientAccountBalance => {
                Self::InsufficientAccountBalance
            }
            AddInvokeTransactionError::ValidationFailure(error) => {
                Self::ValidationFailureV06(error)
            }
            AddInvokeTransactionError::DuplicateTransaction => Self::DuplicateTransaction,
            AddInvokeTransactionError::NonAccount => Self::NonAccount,
            AddInvokeTransactionError::UnsupportedTransactionVersion => Self::UnsupportedTxVersion,
            AddInvokeTransactionError::UnexpectedError(data) => Self::UnexpectedError { data },
        }
    }
}

impl From<SequencerError> for AddInvokeTransactionError {
    fn from(e: SequencerError) -> Self {
        use starknet_gateway_types::error::KnownStarknetErrorCode::{
            DuplicatedTransaction,
            EntryPointNotFound,
            InsufficientAccountBalance,
            InsufficientMaxFee,
            InvalidTransactionNonce,
            InvalidTransactionVersion,
            ValidateFailure,
        };
        match e {
            SequencerError::StarknetError(e) if e.code == DuplicatedTransaction.into() => {
                AddInvokeTransactionError::DuplicateTransaction
            }
            SequencerError::StarknetError(e) if e.code == InsufficientAccountBalance.into() => {
                AddInvokeTransactionError::InsufficientAccountBalance
            }
            SequencerError::StarknetError(e) if e.code == InsufficientMaxFee.into() => {
                AddInvokeTransactionError::InsufficientResourcesForValidate
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionNonce.into() => {
                AddInvokeTransactionError::InvalidTransactionNonce(e.message)
            }
            SequencerError::StarknetError(e) if e.code == ValidateFailure.into() => {
                if e.message.contains("Invalid transaction nonce") {
                    AddInvokeTransactionError::InvalidTransactionNonce(e.message)
                } else {
                    AddInvokeTransactionError::ValidationFailure(e.message)
                }
            }
            SequencerError::StarknetError(e) if e.code == InvalidTransactionVersion.into() => {
                AddInvokeTransactionError::UnsupportedTransactionVersion
            }
            SequencerError::StarknetError(e) if e.code == EntryPointNotFound.into() => {
                AddInvokeTransactionError::NonAccount
            }
            _ => AddInvokeTransactionError::UnexpectedError(e.to_string()),
        }
    }
}

pub async fn add_invoke_transaction(
    context: RpcContext,
    input: Input,
) -> Result<Output, AddInvokeTransactionError> {
    let Transaction::Invoke(tx) = input.invoke_transaction;
    let (transaction_hash, variant) = add_invoke_transaction_impl(&context, tx).await?;
    context.submission_tracker.insert(
        transaction_hash,
        super::get_latest_block_or_genesis(&context.storage)?,
        variant,
    );
    Ok(Output { transaction_hash })
}

pub(crate) async fn add_invoke_transaction_impl(
    context: &RpcContext,
    tx: BroadcastedInvokeTransaction,
) -> Result<(TransactionHash, TransactionVariant), SequencerError> {
    use starknet_gateway_types::request::add_transaction;

    let success = match tx {
        BroadcastedInvokeTransaction::V0(tx) => {
            let response = context
                .sequencer
                .add_invoke_transaction(add_transaction::InvokeFunction::V0(
                    add_transaction::InvokeFunctionV0V1 {
                        max_fee: tx.max_fee,
                        signature: tx.signature.clone(),
                        nonce: None,
                        sender_address: tx.contract_address,
                        entry_point_selector: Some(tx.entry_point_selector),
                        calldata: tx.calldata.clone(),
                    },
                ))
                .await?;
            let new_tx = InvokeTransactionV0 {
                calldata: tx.calldata,
                sender_address: tx.contract_address,
                entry_point_selector: tx.entry_point_selector,
                entry_point_type: None,
                max_fee: tx.max_fee,
                signature: tx.signature,
            };
            (
                response.transaction_hash,
                TransactionVariant::InvokeV0(new_tx),
            )
        }
        BroadcastedInvokeTransaction::V1(tx) => {
            let response = context
                .sequencer
                .add_invoke_transaction(add_transaction::InvokeFunction::V1(
                    add_transaction::InvokeFunctionV0V1 {
                        max_fee: tx.max_fee,
                        signature: tx.signature.clone(),
                        nonce: Some(tx.nonce),
                        sender_address: tx.sender_address,
                        entry_point_selector: None,
                        calldata: tx.calldata.clone(),
                    },
                ))
                .await?;
            let new_tx = InvokeTransactionV1 {
                calldata: tx.calldata,
                sender_address: tx.sender_address,
                max_fee: tx.max_fee,
                signature: tx.signature,
                nonce: tx.nonce,
            };
            (
                response.transaction_hash,
                TransactionVariant::InvokeV1(new_tx),
            )
        }
        BroadcastedInvokeTransaction::V3(tx) => {
            let response = context
                .sequencer
                .add_invoke_transaction(add_transaction::InvokeFunction::V3(
                    add_transaction::InvokeFunctionV3 {
                        signature: tx.signature.clone(),
                        nonce: tx.nonce,
                        nonce_data_availability_mode: tx.nonce_data_availability_mode.into(),
                        fee_data_availability_mode: tx.fee_data_availability_mode.into(),
                        resource_bounds: tx.resource_bounds.into(),
                        tip: tx.tip,
                        paymaster_data: tx.paymaster_data.clone(),
                        sender_address: tx.sender_address,
                        calldata: tx.calldata.clone(),
                        account_deployment_data: tx.account_deployment_data.clone(),
                    },
                ))
                .await?;
            let new_tx = InvokeTransactionV3 {
                signature: tx.signature,
                nonce: tx.nonce,
                nonce_data_availability_mode: tx.nonce_data_availability_mode,
                fee_data_availability_mode: tx.fee_data_availability_mode,
                resource_bounds: tx.resource_bounds,
                tip: tx.tip,
                paymaster_data: tx.paymaster_data,
                account_deployment_data: tx.account_deployment_data,
                calldata: tx.calldata,
                sender_address: tx.sender_address,
                proof_facts: tx.proof_facts,
            };
            (
                response.transaction_hash,
                TransactionVariant::InvokeV3(new_tx),
            )
        }
    };
    Ok(success)
}

impl crate::dto::SerializeForVersion for Output {
    fn serialize(
        &self,
        serializer: crate::dto::Serializer,
    ) -> Result<crate::dto::Ok, crate::dto::Error> {
        let mut serializer = serializer.serialize_struct()?;
        serializer.serialize_field("transaction_hash", &self.transaction_hash)?;
        serializer.end()
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::transaction::{DataAvailabilityMode, ResourceBound, ResourceBounds};
    use pathfinder_common::{ResourceAmount, ResourcePricePerUnit, Tip, TransactionVersion};

    use super::*;
    use crate::types::request::BroadcastedInvokeTransactionV1;

    fn test_invoke_txn() -> Transaction {
        Transaction::Invoke(BroadcastedInvokeTransaction::V1(
            BroadcastedInvokeTransactionV1 {
                version: TransactionVersion::ONE,
                max_fee: fee!("0x4F388496839"),
                signature: vec![
                    transaction_signature_elem!(
                        "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                    ),
                    transaction_signature_elem!(
                        "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                    ),
                ],
                nonce: transaction_nonce!("0x1"),
                sender_address: contract_address!(
                    "023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd"
                ),
                calldata: vec![
                    call_param!("0x1"),
                    call_param!("0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"),
                    call_param!("0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"),
                    call_param!("0x0"),
                    call_param!("0x1"),
                    call_param!("0x1"),
                    call_param!("0x2b"),
                    call_param!("0x0"),
                ],
            },
        ))
    }

    mod parsing {
        use serde_json::json;

        use super::*;
        use crate::dto::{DeserializeForVersion, SerializeForVersion, Serializer};

        #[test]
        fn positional_args() {
            let positional = json!([
                {
                    "type": "INVOKE",
                    "version": "0x1",
                    "max_fee": "0x4f388496839",
                    "signature": [
                        "0x07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                        "0x071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                    ],
                    "nonce": "0x1",
                    "sender_address": "0x023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                    "calldata": [
                        "0x1",
                        "0x0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1",
                        "0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                        "0x0",
                        "0x1",
                        "0x1",
                        "0x2b",
                        "0x0"
                    ]
                }
            ]);

            let input =
                Input::deserialize(crate::dto::Value::new(positional, crate::RpcVersion::V07))
                    .unwrap();
            let expected = Input {
                invoke_transaction: test_invoke_txn(),
            };
            pretty_assertions_sorted::assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = json!({
                "invoke_transaction": {
                    "type": "INVOKE",
                    "version": "0x1",
                    "max_fee": "0x4f388496839",
                    "signature": [
                        "0x07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                        "0x071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                    ],
                    "nonce": "0x1",
                    "sender_address": "0x023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                    "calldata": [
                        "0x1",
                        "0x0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1",
                        "0x0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320",
                        "0x0",
                        "0x1",
                        "0x1",
                        "0x2b",
                        "0x0"
                    ]
                }
            });

            let input =
                Input::deserialize(crate::dto::Value::new(named, crate::RpcVersion::V07)).unwrap();
            let expected = Input {
                invoke_transaction: test_invoke_txn(),
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
                code: StarknetErrorCode::Known(KnownStarknetErrorCode::TransactionLimitExceeded),
                message: "StarkNet Alpha throughput limit reached, please wait a few minutes and \
                          try again."
                    .to_string(),
            });

            let error = AddInvokeTransactionError::from(starknet_error);
            let error = crate::error::ApplicationError::from(error);
            let error = crate::jsonrpc::RpcError::from(error);
            let error = error
                .serialize(Serializer::new(crate::RpcVersion::V07))
                .unwrap();

            let expected = json!({
                "code": 63,
                "message": "An unexpected error occurred",
                "data": "StarkNet Alpha throughput limit reached, please wait a few minutes and try again."
            });

            assert_eq!(error, expected);
        }
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    async fn duplicate_transaction() {
        use crate::types::request::BroadcastedInvokeTransactionV1;

        let context = RpcContext::for_tests();
        let input = BroadcastedInvokeTransactionV1 {
            version: TransactionVersion::ONE,
            max_fee: fee!("0x630a0aff77"),
            signature: vec![
                transaction_signature_elem!(
                    "07ccc81b438581c9360120e0ba0ef52c7d031bdf20a4c2bc3820391b29a8945f"
                ),
                transaction_signature_elem!(
                    "02c11c60d11daaa0043eccdc824bb44f87bc7eb2e9c2437e1654876ab8fa7cad"
                ),
            ],
            nonce: transaction_nonce!("0x2"),
            sender_address: contract_address!(
                "03fdcbeb68e607c8febf01d7ef274cbf68091a0bd1556c0b8f8e80d732f7850f"
            ),
            calldata: vec![
                call_param!("0x1"),
                call_param!("01d809111da75d5e735b6f9573a1ddff78fb6ff7633a0b34273e0c5ddeae349a"),
                call_param!("0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"),
                call_param!("0x0"),
                call_param!("0x1"),
                call_param!("0x1"),
                call_param!("0x1"),
            ],
        };

        let input = Input {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V1(input)),
        };

        let error = add_invoke_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddInvokeTransactionError::DuplicateTransaction);
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    // https://external.integration.starknet.io/feeder_gateway/get_transaction?transactionHash=0x41906f1c314cca5f43170ea75d3b1904196a10101190d2b12a41cc61cfd17c
    async fn duplicate_v3_transaction() {
        use crate::types::request::BroadcastedInvokeTransactionV3;

        let context = RpcContext::for_tests_on(pathfinder_common::Chain::SepoliaIntegration);
        let input = BroadcastedInvokeTransactionV3 {
            version: TransactionVersion::THREE,
            signature: vec![
                transaction_signature_elem!(
                    "0xef42616755b8a9b7c97d2deb1ba4a4176d3c838a20c367072f141af446ee7"
                ),
                transaction_signature_elem!(
                    "0xc6514ea8a88bcb0f4b2a40ddc609461a35af802ba0b35586ade6d8a4be2934"
                ),
            ],
            nonce: transaction_nonce!("0x8a9"),
            resource_bounds: ResourceBounds {
                l1_gas: ResourceBound {
                    max_amount: ResourceAmount(0x186a0),
                    max_price_per_unit: ResourcePricePerUnit(0x5af3107a4000),
                },
                l2_gas: ResourceBound {
                    max_amount: ResourceAmount(0),
                    max_price_per_unit: ResourcePricePerUnit(0),
                },
                l1_data_gas: None,
            },
            tip: Tip(0),
            paymaster_data: vec![],
            account_deployment_data: vec![],
            nonce_data_availability_mode: DataAvailabilityMode::L1,
            fee_data_availability_mode: DataAvailabilityMode::L1,
            sender_address: contract_address!(
                "0x3f6f3bc663aedc5285d6013cc3ffcbc4341d86ab488b8b68d297f8258793c41"
            ),
            calldata: vec![
                call_param!("0x2"),
                call_param!("0x4c312760dfd17a954cdd09e76aa9f149f806d88ec3e402ffaf5c4926f568a42"),
                call_param!("0x31aafc75f498fdfa7528880ad27246b4c15af4954f96228c9a132b328de1c92"),
                call_param!("0x0"),
                call_param!("0x6"),
                call_param!("0x450703c32370cf7ffff540b9352e7ee4ad583af143a361155f2b485c0c39684"),
                call_param!("0xb17d8a2731ba7ca1816631e6be14f0fc1b8390422d649fa27f0fbb0c91eea8"),
                call_param!("0x6"),
                call_param!("0x0"),
                call_param!("0x6"),
                call_param!("0x6333f10b24ed58cc33e9bac40b0d52e067e32a175a97ca9e2ce89fe2b002d82"),
                call_param!("0x3"),
                call_param!("0x602e89fe5703e5b093d13d0a81c9e6d213338dc15c59f4d3ff3542d1d7dfb7d"),
                call_param!("0x20d621301bea11ffd9108af1d65847e9049412159294d0883585d4ad43ad61b"),
                call_param!("0x276faadb842bfcbba834f3af948386a2eb694f7006e118ad6c80305791d3247"),
                call_param!("0x613816405e6334ab420e53d4b38a0451cb2ebca2755171315958c87d303cf6"),
            ],
            proof_facts: vec![],
        };

        let input = Input {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V3(input)),
        };

        let error = add_invoke_transaction(context, input).await.unwrap_err();
        assert_matches::assert_matches!(error, AddInvokeTransactionError::DuplicateTransaction);
    }
}
