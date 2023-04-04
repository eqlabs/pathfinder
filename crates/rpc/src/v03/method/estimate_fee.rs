use crate::{
    context::RpcContext,
    v02::types::{reply::FeeEstimate, request::BroadcastedTransaction},
};
use pathfinder_common::BlockId;

use super::common::prepare_handle_and_block;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: Vec<BroadcastedTransaction>,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError,
    InvalidMessageSelector,
    InvalidCallData
);

impl From<crate::cairo::ext_py::CallFailure> for EstimateFeeError {
    fn from(c: crate::cairo::ext_py::CallFailure) -> Self {
        use crate::cairo::ext_py::CallFailure::*;
        match c {
            NoSuchBlock => Self::BlockNotFound,
            NoSuchContract => Self::ContractNotFound,
            InvalidEntryPoint => Self::InvalidMessageSelector,
            ExecutionFailed(e) => Self::Internal(anyhow::anyhow!("Internal error: {e}")),
            // Intentionally hide the message under Internal
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<Vec<FeeEstimate>, EstimateFeeError> {
    let (handle, gas_price, when, pending_timestamp, pending_update) =
        prepare_handle_and_block(&context, input.block_id).await?;

    let result = handle
        .estimate_fee(
            input.request,
            when,
            gas_price,
            pending_update,
            pending_timestamp,
        )
        .await?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransaction;
    use pathfinder_common::{
        felt, CallParam, ContractAddress, Fee, StarknetBlockHash, TransactionNonce,
        TransactionSignatureElem, TransactionVersion,
    };

    mod parsing {
        use super::*;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                crate::v02::types::request::BroadcastedInvokeTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(felt!("0x6")),
                    signature: vec![TransactionSignatureElem(felt!("0x7"))],
                    nonce: TransactionNonce(felt!("0x8")),
                    sender_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                    calldata: vec![CallParam(felt!("0xff"))],
                },
            ))
        }

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
                [
                    {
                        "type": "INVOKE",
                        "version": "0x100000000000000000000000000000001",
                        "max_fee": "0x6",
                        "signature": [
                            "0x7"
                        ],
                        "nonce": "0x8",
                        "sender_address": "0xaaa",
                        "calldata": [
                            "0xff"
                        ]
                    }
                ],
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(StarknetBlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
                "request": [
                    {
                        "type": "INVOKE",
                        "version": "0x100000000000000000000000000000001",
                        "max_fee": "0x6",
                        "signature": [
                            "0x7"
                        ],
                        "nonce": "0x8",
                        "sender_address": "0xaaa",
                        "calldata": [
                            "0xff"
                        ]
                    }
                ],
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: vec![test_invoke_txn()],
                block_id: BlockId::Hash(StarknetBlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    // These tests require a Python environment properly set up _and_ a mainnet database with the first six blocks.
    mod ext_py {
        use std::path::PathBuf;
        use std::sync::Arc;

        use super::*;
        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV1,
            BroadcastedInvokeTransactionV1,
        };
        use crate::v02::types::{CairoContractClass, ContractClass};
        use pathfinder_common::{felt_bytes, Chain};
        use pathfinder_storage::JournalMode;

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(StarknetBlockHash(felt!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_invoke_v1() -> BroadcastedInvokeTransactionV1 {
            BroadcastedInvokeTransactionV1 {
                version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                max_fee: Fee(Default::default()),
                signature: vec![],
                nonce: TransactionNonce(Default::default()),
                sender_address: ContractAddress::new_or_panic(felt!(
                    "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                )),
                calldata: vec![
                    CallParam(felt!(
                        "e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"
                    )),
                    CallParam(felt!(
                        "0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"
                    )),
                ],
            }
        }

        // fn deploy_account_transaction() -> BroadcastedTransaction {
        //     BroadcastedTransaction::DeployAccount(BroadcastedDeployAccountTransaction {
        //         version: TransactionVersion::ONE_WITH_QUERY_VERSION,
        //         max_fee: Fee(H128::zero()),
        //         signature: vec![],
        //         nonce: TransactionNonce::ZERO,
        //         contract_address_salt: ContractAddressSalt(Felt::ZERO),
        //         constructor_calldata: vec![CallParam(Felt::ZERO)],
        //         class_hash: ClassHash(felt!(
        //             "0x00AF5F6EE1C2AD961F0B1CD3FA4285CEFAD65A418DD105719FAA5D47583EB0A8"
        //         )),
        //     })
        // }

        // fn invoke_v1_transaction(account: ) ->

        fn valid_broadcasted_transaction() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V1(
                valid_mainnet_invoke_v1(),
            ))
        }

        async fn test_context_with_call_handling() -> (RpcContext, tokio::task::JoinHandle<()>) {
            use pathfinder_common::ChainId;

            let mut database_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            database_path.push("fixtures/mainnet.sqlite");
            let storage =
                pathfinder_storage::Storage::migrate(database_path.clone(), JournalMode::WAL)
                    .unwrap();
            let sync_state = Arc::new(crate::SyncState::default());
            let (call_handle, cairo_handle) = crate::cairo::ext_py::start(
                storage.path().into(),
                std::num::NonZeroUsize::try_from(2).unwrap(),
                futures::future::pending(),
                Chain::Mainnet,
            )
            .await
            .unwrap();

            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();
            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);
            (context.with_call_handling(call_handle), cairo_handle)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: vec![valid_broadcasted_transaction()],
                block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let mainnet_invoke = valid_mainnet_invoke_v1();
            let input = EstimateFeeInput {
                request: vec![BroadcastedTransaction::Invoke(
                    BroadcastedInvokeTransaction::V1(BroadcastedInvokeTransactionV1 {
                        sender_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
                        ..mainnet_invoke
                    }),
                )],
                block_id: BLOCK_5,
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::ContractNotFound));
        }

        #[tokio::test]
        async fn successful_invoke_v1() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: vec![
                    valid_broadcasted_transaction(),
                    valid_broadcasted_transaction(),
                ],
                block_id: BLOCK_5,
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(
                result,
                vec![FeeEstimate::default(), FeeEstimate::default(),]
            );
        }

        lazy_static::lazy_static! {
            pub static ref CONTRACT_CLASS: CairoContractClass = {
                let compressed_json = starknet_gateway_test_fixtures::zstd_compressed_contracts::CONTRACT_DEFINITION;
                let json = zstd::decode_all(compressed_json).unwrap();
                ContractClass::from_definition_bytes(&json).unwrap().as_cairo().unwrap()
            };
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v1() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V1(BroadcastedDeclareTransactionV1 {
                    version: TransactionVersion::ONE_WITH_QUERY_VERSION,
                    max_fee: Fee(Default::default()),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class: CONTRACT_CLASS.clone(),
                    sender_address: ContractAddress::new_or_panic(felt!("01")),
                }),
            );

            let input = EstimateFeeInput {
                request: vec![declare_transaction],
                block_id: BLOCK_5,
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(result, vec![FeeEstimate::default()]);
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v2() {}
    }
}
