use crate::{
    core::{BlockId, CallParam, CallResultValue, ContractAddress, EntryPoint},
    rpc::v02::RpcContext,
};

crate::rpc::error::generate_rpc_error_subset!(
    CallError: BlockNotFound,
    ContractNotFound,
    InvalidMessageSelector,
    InvalidCallData,
    ContractError
);

impl From<crate::cairo::ext_py::CallFailure> for CallError {
    fn from(c: crate::cairo::ext_py::CallFailure) -> Self {
        use crate::cairo::ext_py::CallFailure::*;
        match c {
            NoSuchBlock => Self::BlockNotFound,
            NoSuchContract => Self::ContractNotFound,
            InvalidEntryPoint => Self::InvalidMessageSelector,
            ExecutionFailed(e) => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
            // Intentionally hide the message under Internal
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct CallInput {
    request: FunctionCall,
    block_id: BlockId,
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct FunctionCall {
    pub contract_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub calldata: Vec<CallParam>,
}

impl From<FunctionCall> for crate::rpc::v01::types::request::Call {
    fn from(call: FunctionCall) -> Self {
        Self {
            contract_address: call.contract_address,
            calldata: call.calldata,
            entry_point_selector: Some(call.entry_point_selector),
            // TODO: these fields are estimateFee-only and effectively ignored
            // by the underlying implementation. We can remove these once
            // JSON-RPC v0.1.0 is removed.
            signature: vec![],
            max_fee: Self::DEFAULT_MAX_FEE,
            version: Self::DEFAULT_VERSION,
            nonce: Self::DEFAULT_NONCE,
        }
    }
}

pub async fn call(
    context: RpcContext,
    input: CallInput,
) -> Result<Vec<CallResultValue>, CallError> {
    let handle = context
        .call_handle
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Unsupported configuration"))?;

    let (when, pending_update) =
        super::estimate_fee::base_block_and_pending_for_call(input.block_id, &context.pending_data)
            .await?;

    let result = handle
        .call(input.request.into(), when, pending_update)
        .await?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::starkhash;

    mod parsing {
        use crate::core::StarknetBlockHash;

        use super::*;

        use jsonrpsee::types::Params;

        #[test]
        fn positional_args() {
            let positional = r#"[
                { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                { "block_hash": "0xbbbbbbbb" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<CallInput>().unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(starkhash!("0abcde")),
                    entry_point_selector: EntryPoint(starkhash!("ee")),
                    calldata: vec![CallParam(starkhash!("1234")), CallParam(starkhash!("2345"))],
                },
                block_id: StarknetBlockHash(starkhash!("bbbbbbbb")).into(),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            let named = r#"{
                "request": { "contract_address": "0xabcde", "entry_point_selector": "0xee", "calldata": ["0x1234", "0x2345"] },
                "block_id": { "block_hash": "0xbbbbbbbb" }
            }"#;
            let named = Params::new(Some(named));

            let input = named.parse::<CallInput>().unwrap();
            let expected = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(starkhash!("0abcde")),
                    entry_point_selector: EntryPoint(starkhash!("ee")),
                    calldata: vec![CallParam(starkhash!("1234")), CallParam(starkhash!("2345"))],
                },
                block_id: StarknetBlockHash(starkhash!("bbbbbbbb")).into(),
            };
            assert_eq!(input, expected);
        }
    }

    mod ext_py {
        use std::path::PathBuf;
        use std::sync::Arc;

        use crate::core::{Chain, StarknetBlockHash};
        use crate::starkhash_bytes;
        use crate::storage::JournalMode;

        use super::*;

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_call() -> FunctionCall {
            FunctionCall {
                contract_address: ContractAddress::new_or_panic(starkhash!(
                    "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                )),
                entry_point_selector: EntryPoint(starkhash!(
                    "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
                )),
                calldata: vec![
                    CallParam(starkhash!(
                        "e150b6c2db6ed644483b01685571de46d2045f267d437632b508c19f3eb877"
                    )),
                    CallParam(starkhash!(
                        "0494196e88ce16bff11180d59f3c75e4ba3475d9fba76249ab5f044bcd25add6"
                    )),
                ],
            }
        }

        async fn test_context_with_call_handling() -> (RpcContext, tokio::task::JoinHandle<()>) {
            let mut database_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            database_path.push("fixtures/mainnet.sqlite");
            let storage =
                crate::storage::Storage::migrate(database_path.clone(), JournalMode::WAL).unwrap();
            let sync_state = Arc::new(crate::state::SyncState::default());
            let (call_handle, cairo_handle) = crate::cairo::ext_py::start(
                storage.path().into(),
                std::num::NonZeroUsize::try_from(2).unwrap(),
                futures::future::pending(),
                Chain::Mainnet,
            )
            .await
            .unwrap();

            let chain = Chain::Mainnet;
            let sequencer = crate::sequencer::Client::new(chain).unwrap();

            let context = RpcContext::new(storage, sync_state, chain, sequencer);
            (context.with_call_handling(call_handle), cairo_handle)
        }

        #[tokio::test]
        async fn no_such_block() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"nonexistent"))),
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(starkhash!("deadbeef")),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::ContractNotFound));
        }

        #[tokio::test]
        async fn invalid_message_selector() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = CallInput {
                request: FunctionCall {
                    entry_point_selector: EntryPoint(Default::default()),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::InvalidMessageSelector));
        }

        #[tokio::test]
        async fn successful_call() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BLOCK_5,
            };

            let result = call(context, input).await.unwrap();
            assert_eq!(result, vec![]);
        }
    }
}
