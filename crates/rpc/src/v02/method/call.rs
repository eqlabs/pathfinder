use std::sync::Arc;

use crate::context::RpcContext;
use crate::felt::RpcFelt;
use anyhow::Context;
use pathfinder_common::{
    BlockId, CallParam, CallResultValue, ContractAddress, EntryPoint, StarknetBlockTimestamp,
};
use pathfinder_storage::{StarknetBlocksBlockId, StarknetBlocksTable};
use starknet_gateway_types::pending::PendingData;

crate::error::generate_rpc_error_subset!(
    CallError: BlockNotFound,
    ContractNotFound,
    InvalidMessageSelector,
    InvalidCallData,
    ContractError
);

impl From<starknet_rs::business_logic::transaction::error::TransactionError> for CallError {
    fn from(value: starknet_rs::business_logic::transaction::error::TransactionError) -> Self {
        use starknet_rs::business_logic::transaction::error::TransactionError;
        match value {
            TransactionError::EntryPointNotFound => Self::InvalidMessageSelector,
            TransactionError::FailToReadClassHash => Self::ContractNotFound,
            e => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
        }
    }
}

impl From<crate::cairo::starknet_rs::CallError> for CallError {
    fn from(value: crate::cairo::starknet_rs::CallError) -> Self {
        use crate::cairo::starknet_rs::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::InvalidMessageSelector,
            Internal(e) => Self::Internal(e),
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

#[serde_with::serde_as]
#[derive(serde::Serialize, Debug)]
pub struct CallOutput(#[serde_as(as = "Vec<RpcFelt>")] Vec<CallResultValue>);

pub async fn call(context: RpcContext, input: CallInput) -> Result<CallOutput, CallError> {
    let (block_id, _pending_timestamp, _pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction().context("Creating database transaction")?;

        let storage_commitment = StarknetBlocksTable::get_storage_commitment(&tx, block_id)
            .context("Reading storage root for block")?
            .ok_or_else(|| CallError::BlockNotFound)?;

        let result = crate::cairo::starknet_rs::do_call(
            context.storage,
            storage_commitment,
            input.request.contract_address,
            input.request.entry_point_selector,
            input.request.calldata,
        )?;

        Ok(result)
    })
    .await
    .context("Executing call")?;

    result.map(CallOutput)
}

/// Transforms pending requests into latest + optional pending data to apply.
async fn base_block_and_pending_for_call(
    at_block: BlockId,
    pending_data: &Option<PendingData>,
) -> Result<
    (
        StarknetBlocksBlockId,
        Option<StarknetBlockTimestamp>,
        Option<Arc<starknet_gateway_types::reply::PendingStateUpdate>>,
    ),
    anyhow::Error,
> {
    match at_block {
        BlockId::Pending => {
            // we must have pending_data configured for pending requests, otherwise we fail
            // fast.
            match pending_data {
                Some(pending) => {
                    // call on this particular parent block hash; if it's not found at query time over
                    // at python, it should fall back to latest and **disregard** the pending data.
                    let pending_on_top_of_a_block = pending
                        .state_update_on_parent_block()
                        .await
                        .map(|(parent_block, timestamp, data)| {
                            (parent_block.into(), Some(timestamp), Some(data))
                        });

                    // if there is no pending data available, just execute on whatever latest.
                    Ok(pending_on_top_of_a_block.unwrap_or((
                        StarknetBlocksBlockId::Latest,
                        None,
                        None,
                    )))
                }
                None => Err(anyhow::anyhow!(
                    "Pending data not supported in this configuration"
                )),
            }
        }
        BlockId::Number(n) => Ok((StarknetBlocksBlockId::Number(n), None, None)),
        BlockId::Hash(h) => Ok((StarknetBlocksBlockId::Hash(h), None, None)),
        BlockId::Latest => Ok((StarknetBlocksBlockId::Latest, None, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pathfinder_common::felt;

    mod parsing {
        use super::*;
        use jsonrpsee::types::Params;
        use pathfinder_common::StarknetBlockHash;

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
                    contract_address: ContractAddress::new_or_panic(felt!("0xabcde")),
                    entry_point_selector: EntryPoint(felt!("0xee")),
                    calldata: vec![CallParam(felt!("0x1234")), CallParam(felt!("0x2345"))],
                },
                block_id: StarknetBlockHash(felt!("0xbbbbbbbb")).into(),
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
                    contract_address: ContractAddress::new_or_panic(felt!("0xabcde")),
                    entry_point_selector: EntryPoint(felt!("0xee")),
                    calldata: vec![CallParam(felt!("0x1234")), CallParam(felt!("0x2345"))],
                },
                block_id: StarknetBlockHash(felt!("0xbbbbbbbb")).into(),
            };
            assert_eq!(input, expected);
        }
    }

    mod ext_py {
        use super::*;
        use pathfinder_common::{felt_bytes, Chain, StarknetBlockHash};
        use pathfinder_storage::JournalMode;
        use std::path::PathBuf;
        use std::sync::Arc;

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(StarknetBlockHash(felt!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_call() -> FunctionCall {
            FunctionCall {
                contract_address: ContractAddress::new_or_panic(felt!(
                    "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                )),
                entry_point_selector: EntryPoint(felt!(
                    "03d7905601c217734671143d457f0db37f7f8883112abd34b92c4abfeafde0c3"
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

        async fn test_context_with_call_handling() -> RpcContext {
            use pathfinder_common::ChainId;

            let mut database_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            database_path.push("fixtures/mainnet.sqlite");
            let storage =
                pathfinder_storage::Storage::migrate(database_path.clone(), JournalMode::WAL)
                    .unwrap();
            let sync_state = Arc::new(crate::SyncState::default());

            let sequencer = starknet_gateway_client::Client::new(Chain::Mainnet).unwrap();

            RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer)
        }

        #[tokio::test]
        async fn no_such_block() {
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: FunctionCall {
                    contract_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
                    ..valid_mainnet_call()
                },
                block_id: BLOCK_5,
            };
            let error = call(context, input).await;
            assert_matches::assert_matches!(error, Err(CallError::ContractNotFound));
        }

        #[tokio::test]
        async fn invalid_message_selector() {
            let context = test_context_with_call_handling().await;

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
            let context = test_context_with_call_handling().await;

            let input = CallInput {
                request: valid_mainnet_call(),
                block_id: BLOCK_5,
            };

            let result = call(context, input).await.unwrap();
            assert_eq!(result.0, vec![]);
        }
    }
}
