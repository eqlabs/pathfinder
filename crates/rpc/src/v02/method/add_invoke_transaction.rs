use crate::felt::RpcFelt;
use crate::v02::types::request::BroadcastedInvokeTransaction;
use crate::v02::RpcContext;
use anyhow::Context;
use pathfinder_common::StarknetTransactionHash;
use starknet_gateway_client::ClientApi;

crate::error::generate_rpc_error_subset!(AddInvokeTransactionError);

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
    transaction_hash: StarknetTransactionHash,
}

pub async fn add_invoke_transaction(
    context: RpcContext,
    input: AddInvokeTransactionInput,
) -> Result<AddInvokeTransactionOutput, AddInvokeTransactionError> {
    let Transaction::Invoke(tx) = input.invoke_transaction;
    let response = match tx {
        BroadcastedInvokeTransaction::V0(v0) => context
            .sequencer
            .add_invoke_transaction(
                v0.version,
                v0.max_fee,
                v0.signature,
                // Nonce is part of the RPC specification for V0 but this
                // is a bug in the spec. The gateway won't accept it, so
                // we null it out.
                None,
                v0.contract_address,
                Some(v0.entry_point_selector),
                v0.calldata,
            )
            .await
            .context("Sending V0 invoke transaction to gateway")?,
        BroadcastedInvokeTransaction::V1(v1) => context
            .sequencer
            .add_invoke_transaction(
                v1.version,
                v1.max_fee,
                v1.signature,
                Some(v1.nonce),
                v1.sender_address,
                None,
                v1.calldata,
            )
            .await
            .context("Sending V1 invoke transaction to gateway")?,
    };

    Ok(AddInvokeTransactionOutput {
        transaction_hash: response.transaction_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransactionV0;
    use pathfinder_common::{
        felt, CallParam, ContractAddress, EntryPoint, Fee, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };

    fn test_invoke_txn() -> Transaction {
        Transaction::Invoke(BroadcastedInvokeTransaction::V0(
            BroadcastedInvokeTransactionV0 {
                version: TransactionVersion::ZERO,
                max_fee: Fee(5444010076217u128.to_be_bytes().into()),
                signature: vec![
                    TransactionSignatureElem(felt!(
                        "07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5"
                    )),
                    TransactionSignatureElem(felt!(
                        "071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                    )),
                ],
                nonce: None,
                contract_address: ContractAddress::new_or_panic(felt!(
                    "023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd"
                )),
                entry_point_selector: EntryPoint(felt!(
                    "015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad"
                )),
                calldata: vec![
                    CallParam(felt!("0x1")),
                    CallParam(felt!(
                        "0677bb1cdc050e8d63855e8743ab6e09179138def390676cc03c484daf112ba1"
                    )),
                    CallParam(felt!(
                        "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                    )),
                    CallParam(felt!("0x0")),
                    CallParam(felt!("0x1")),
                    CallParam(felt!("0x1")),
                    CallParam(felt!("0x2b")),
                    CallParam(felt!("0x0")),
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
                    "version": "0x0",
                    "max_fee": "0x4f388496839",
                    "signature": [
                        "0x07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                        "0x071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                    ],
                    "nonce": null,
                    "contract_address": "0x023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                    "entry_point_selector": "0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
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
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named = r#"{
                "invoke_transaction": {
                    "type": "INVOKE",
                    "version": "0x0",
                    "max_fee": "0x4f388496839",
                    "signature": [
                        "0x07dd3a55d94a0de6f3d6c104d7e6c88ec719a82f4e2bbc12587c8c187584d3d5",
                        "0x071456dded17015d1234779889d78f3e7c763ddcfd2662b19e7843c7542614f8"
                    ],
                    "nonce": null,
                    "contract_address": "0x023371b227eaecd8e8920cd429357edddd2cd0f3fee6abaacca08d3ab82a7cdd",
                    "entry_point_selector": "0x015d40a3d6ca2ac30f4031e42be28da9b056fef9bb7357ac5e85627ee876e5ad",
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
    async fn invoke_v0() {
        let context = RpcContext::for_tests();
        let input = AddInvokeTransactionInput {
            invoke_transaction: test_invoke_txn(),
        };
        let expected = AddInvokeTransactionOutput {
            transaction_hash: StarknetTransactionHash(felt!(
                "0389dd0629f42176cc8b6c43acefc0713d0064ecdfc0470e0fc179f53421a38b"
            )),
        };

        let result = add_invoke_transaction(context, input).await.unwrap();
        assert_eq!(result, expected);
    }

    #[tokio::test]
    #[ignore = "gateway 429"]
    async fn invoke_v1() {
        use crate::v02::types::request::BroadcastedInvokeTransactionV1;

        let context = RpcContext::for_tests();
        let input = BroadcastedInvokeTransactionV1 {
            version: TransactionVersion::ONE,
            max_fee: Fee(ethers::types::H128::from_low_u64_be(0x630a0aff77)),
            signature: vec![
                TransactionSignatureElem(felt!(
                    "07ccc81b438581c9360120e0ba0ef52c7d031bdf20a4c2bc3820391b29a8945f"
                )),
                TransactionSignatureElem(felt!(
                    "02c11c60d11daaa0043eccdc824bb44f87bc7eb2e9c2437e1654876ab8fa7cad"
                )),
            ],
            nonce: TransactionNonce(felt!("0x2")),
            sender_address: ContractAddress::new_or_panic(felt!(
                "03fdcbeb68e607c8febf01d7ef274cbf68091a0bd1556c0b8f8e80d732f7850f"
            )),
            calldata: vec![
                CallParam(felt!("0x1")),
                CallParam(felt!(
                    "01d809111da75d5e735b6f9573a1ddff78fb6ff7633a0b34273e0c5ddeae349a"
                )),
                CallParam(felt!(
                    "0362398bec32bc0ebb411203221a35a0301193a96f317ebe5e40be9f60d15320"
                )),
                CallParam(felt!("0x0")),
                CallParam(felt!("0x1")),
                CallParam(felt!("0x1")),
                CallParam(felt!("0x1")),
            ],
        };

        let input = AddInvokeTransactionInput {
            invoke_transaction: Transaction::Invoke(BroadcastedInvokeTransaction::V1(input)),
        };
        let expected = AddInvokeTransactionOutput {
            transaction_hash: StarknetTransactionHash(felt!(
                "040397a2e590c9707d73cc63ec54683c2d155b65d2e990d6f53d48a395eb3997"
            )),
        };

        let result = add_invoke_transaction(context, input).await.unwrap();
        assert_eq!(result, expected);
    }
}
