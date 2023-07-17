use crate::context::RpcContext;
use crate::felt::RpcFelt;
use crate::v02::types::request::BroadcastedInvokeTransaction;
use pathfinder_common::TransactionHash;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::error::{SequencerError, StarknetError};

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum Transaction {
    #[serde(rename = "INVOKE")]
    Invoke(BroadcastedInvokeTransaction),
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct AddInvokeTransactionInput {
    invoke_transaction: Transaction,
}

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug, PartialEq, Eq)]
pub struct AddInvokeTransactionOutput {
    #[serde_as(as = "RpcFelt")]
    transaction_hash: TransactionHash,
}

#[derive(Debug)]
pub enum AddInvokeTransactionError {
    GatewayError(StarknetError),
    Internal(anyhow::Error),
}

impl From<AddInvokeTransactionError> for crate::error::RpcError {
    fn from(value: AddInvokeTransactionError) -> Self {
        match value {
            AddInvokeTransactionError::GatewayError(x) => Self::GatewayError(x),
            AddInvokeTransactionError::Internal(x) => Self::Internal(x),
        }
    }
}

impl From<anyhow::Error> for AddInvokeTransactionError {
    fn from(value: anyhow::Error) -> Self {
        AddInvokeTransactionError::Internal(value)
    }
}

pub async fn add_invoke_transaction(
    context: RpcContext,
    input: AddInvokeTransactionInput,
) -> Result<AddInvokeTransactionOutput, AddInvokeTransactionError> {
    let Transaction::Invoke(tx) = input.invoke_transaction;
    let response = match tx {
        BroadcastedInvokeTransaction::V1(v1) => context
            .sequencer
            .add_invoke_transaction(
                v1.version,
                v1.max_fee,
                v1.signature,
                v1.nonce,
                v1.sender_address,
                v1.calldata,
            )
            .await
            .map_err(|e| match e {
                SequencerError::StarknetError(e) => AddInvokeTransactionError::GatewayError(e),
                other => AddInvokeTransactionError::Internal(other.into()),
            })?,
    };

    Ok(AddInvokeTransactionOutput {
        transaction_hash: response.transaction_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransactionV1;
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::TransactionVersion;

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
        use super::*;

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
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
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<AddInvokeTransactionInput>().unwrap();
            let expected = AddInvokeTransactionInput {
                invoke_transaction: test_invoke_txn(),
            };
            pretty_assertions::assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named = r#"{
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
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<AddInvokeTransactionInput>().unwrap();
            let expected = AddInvokeTransactionInput {
                invoke_transaction: test_invoke_txn(),
            };
            assert_eq!(input, expected);
        }
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    async fn invoke_v1() {
        use crate::v02::types::request::BroadcastedInvokeTransactionV1;

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

        let input = AddInvokeTransactionInput {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V1(input)),
        };
        let expected = AddInvokeTransactionOutput {
            transaction_hash: transaction_hash!(
                "040397a2e590c9707d73cc63ec54683c2d155b65d2e990d6f53d48a395eb3997"
            ),
        };

        let result = add_invoke_transaction(context, input).await.unwrap();
        assert_eq!(result, expected);
    }
}
