use crate::{
    cairo::ext_py::{BlockHashNumberOrLatest, GasPriceSource},
    rpc::v02::types::request::BroadcastedTransaction,
    rpc::v02::RpcContext,
    state::PendingData,
};
use pathfinder_common::{BlockId, StarknetBlockTimestamp};
use serde::Serialize;
use serde_with::serde_as;
use std::sync::Arc;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: BroadcastedTransaction,
    block_id: BlockId,
}

crate::rpc::error::generate_rpc_error_subset!(
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
            ExecutionFailed(e) => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
            // Intentionally hide the message under Internal
            Internal(_) | Shutdown => Self::Internal(anyhow::anyhow!("Internal error")),
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<FeeEstimate, EstimateFeeError> {
    let handle = context
        .call_handle
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Unsupported configuration"))?;

    // discussed during estimateFee work: when user is requesting using block_hash use the
    // gasPrice from the starknet_blocks::gas_price column, otherwise (tags) get the latest
    // eth_gasPrice.
    //
    // the fact that [`base_block_and_pending_for_call`] transforms pending cases to use
    // actual parent blocks by hash is an internal transformation we do for correctness,
    // unrelated to this consideration.
    let gas_price = if matches!(input.block_id, BlockId::Pending | BlockId::Latest) {
        let gas_price = match context.eth_gas_price.as_ref() {
            Some(cached) => cached.get().await,
            None => None,
        };

        let gas_price =
            gas_price.ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))?;

        GasPriceSource::Current(gas_price)
    } else {
        GasPriceSource::PastBlock
    };

    let (when, pending_timestamp, pending_update) =
        base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;

    let result = handle
        .estimate_fee(
            input.request,
            when,
            gas_price,
            pending_update,
            pending_timestamp,
        )
        .await?;

    Ok(result.into())
}

/// Transforms the request to call or estimate fee at some point in time to the type expected
/// by [`crate::cairo::ext_py`] with the optional, latest pending data.
pub(super) async fn base_block_and_pending_for_call(
    at_block: BlockId,
    pending_data: &Option<PendingData>,
) -> Result<
    (
        BlockHashNumberOrLatest,
        Option<StarknetBlockTimestamp>,
        Option<Arc<crate::sequencer::reply::StateUpdate>>,
    ),
    anyhow::Error,
> {
    use crate::cairo::ext_py::Pending;

    match BlockHashNumberOrLatest::try_from(at_block) {
        Ok(when) => Ok((when, None, None)),
        Err(Pending) => {
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
                        BlockHashNumberOrLatest::Latest,
                        None,
                        None,
                    )))
                }
                None => Err(anyhow::anyhow!(
                    "Pending data not supported in this configuration"
                )),
            }
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[cfg_attr(any(test, feature = "rpc-full-serde"), derive(serde::Deserialize))]
#[serde(deny_unknown_fields)]
pub struct FeeEstimate {
    /// The Ethereum gas cost of the transaction
    #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
    pub gas_consumed: web3::types::H256,
    /// The gas price (in gwei) that was used in the cost estimation (input to fee estimation)
    #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
    pub gas_price: web3::types::H256,
    /// The estimated fee for the transaction (in gwei), product of gas_consumed and gas_price
    #[serde_as(as = "pathfinder_serde::H256AsHexStr")]
    pub overall_fee: web3::types::H256,
}

impl From<crate::rpc::v01::types::reply::FeeEstimate> for FeeEstimate {
    fn from(v01: crate::rpc::v01::types::reply::FeeEstimate) -> Self {
        Self {
            gas_consumed: v01.consumed,
            gas_price: v01.gas_price,
            overall_fee: v01.fee,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rpc::v02::types::request::BroadcastedInvokeTransaction, storage::JournalMode};
    use pathfinder_common::{
        starkhash, CallParam, Chain, ContractAddress, EntryPoint, Fee, StarknetBlockHash,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use std::path::PathBuf;

    mod parsing {
        use super::*;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                crate::rpc::v02::types::request::BroadcastedInvokeTransactionV0 {
                    version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                    max_fee: Fee(web3::types::H128::from_low_u64_be(0x6)),
                    signature: vec![TransactionSignatureElem(starkhash!("07"))],
                    nonce: Some(TransactionNonce(starkhash!("08"))),
                    contract_address: ContractAddress::new_or_panic(starkhash!("0aaa")),
                    entry_point_selector: EntryPoint(starkhash!("0e")),
                    calldata: vec![CallParam(starkhash!("ff"))],
                },
            ))
        }

        #[test]
        fn positional_args() {
            use jsonrpsee::types::Params;

            let positional = r#"[
                {
                    "type": "INVOKE",
                    "version": "0x100000000000000000000000000000000",
                    "max_fee": "0x6",
                    "signature": [
                        "0x7"
                    ],
                    "nonce": "0x8",
                    "contract_address": "0xaaa",
                    "entry_point_selector": "0xe",
                    "calldata": [
                        "0xff"
                    ]
                },
                { "block_hash": "0xabcde" }
            ]"#;
            let positional = Params::new(Some(positional));

            let input = positional.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: test_invoke_txn(),
                block_id: BlockId::Hash(StarknetBlockHash(starkhash!("0abcde"))),
            };
            assert_eq!(input, expected);
        }

        #[test]
        fn named_args() {
            use jsonrpsee::types::Params;

            let named_args = r#"{
                "request": {
                    "type": "INVOKE",
                    "version": "0x100000000000000000000000000000000",
                    "max_fee": "0x6",
                    "signature": [
                        "0x7"
                    ],
                    "nonce": "0x8",
                    "contract_address": "0xaaa",
                    "entry_point_selector": "0xe",
                    "calldata": [
                        "0xff"
                    ]
                },
                "block_id": { "block_hash": "0xabcde" }
            }"#;
            let named_args = Params::new(Some(named_args));

            let input = named_args.parse::<EstimateFeeInput>().unwrap();
            let expected = EstimateFeeInput {
                request: test_invoke_txn(),
                block_id: BlockId::Hash(StarknetBlockHash(starkhash!("0abcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    // These tests require a Python environment properly set up _and_ a mainnet database with the first six blocks.
    mod ext_py {
        use super::*;
        use crate::rpc::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeployTransaction,
            BroadcastedInvokeTransactionV0,
        };
        use crate::rpc::v02::types::ContractClass;
        use pathfinder_common::{starkhash_bytes, ContractAddressSalt};

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(StarknetBlockHash(starkhash!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_invoke_v0() -> BroadcastedInvokeTransactionV0 {
            BroadcastedInvokeTransactionV0 {
                version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                max_fee: Fee(Default::default()),
                signature: vec![],
                nonce: Some(TransactionNonce(Default::default())),
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

        fn valid_broadcasted_transaction() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                valid_mainnet_invoke_v0(),
            ))
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

            let input = EstimateFeeInput {
                request: valid_broadcasted_transaction(),
                block_id: BlockId::Hash(StarknetBlockHash(starkhash_bytes!(b"nonexistent"))),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let mainnet_invoke = valid_mainnet_invoke_v0();
            let input = EstimateFeeInput {
                request: BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                    BroadcastedInvokeTransactionV0 {
                        contract_address: ContractAddress::new_or_panic(starkhash!("deadbeef")),
                        ..mainnet_invoke
                    },
                )),
                block_id: BLOCK_5,
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::ContractNotFound));
        }

        #[tokio::test]
        async fn invalid_message_selector() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let mainnet_invoke = valid_mainnet_invoke_v0();
            let input = EstimateFeeInput {
                request: BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                    BroadcastedInvokeTransactionV0 {
                        entry_point_selector: EntryPoint(Default::default()),
                        ..mainnet_invoke
                    },
                )),
                block_id: BLOCK_5,
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::InvalidMessageSelector));
        }

        #[tokio::test]
        async fn successful_invoke_v0() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: valid_broadcasted_transaction(),
                block_id: BLOCK_5,
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(
                result,
                FeeEstimate {
                    gas_consumed: Default::default(),
                    gas_price: Default::default(),
                    overall_fee: Default::default()
                }
            );
        }

        lazy_static::lazy_static! {
            pub static ref CONTRACT_CLASS: ContractClass = {
                let compressed_json = include_bytes!("../../../../fixtures/contract_definition.json.zst");
                let json = zstd::decode_all(std::io::Cursor::new(compressed_json)).unwrap();
                ContractClass::from_definition_bytes(&json).unwrap()
            };
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let declare_transaction =
                BroadcastedTransaction::Declare(BroadcastedDeclareTransaction {
                    version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                    max_fee: Fee(Default::default()),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class: CONTRACT_CLASS.clone(),
                    sender_address: ContractAddress::new_or_panic(starkhash!(
                        "020cfa74ee3564b4cd5435cdace0f9c4d43b939620e4a0bb5076105df0a626c6"
                    )),
                });

            let input = EstimateFeeInput {
                request: declare_transaction,
                block_id: BLOCK_5,
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(
                result,
                FeeEstimate {
                    gas_consumed: Default::default(),
                    gas_price: Default::default(),
                    overall_fee: Default::default()
                }
            );
        }

        // The cairo-lang Python implementation does not support estimating deploy transactions.
        // According to Starkware these transactions are subsidized so the fee should be zero.
        #[test_log::test(tokio::test)]
        async fn deploy_returns_zero() {
            let (context, _join_handle) = test_context_with_call_handling().await;

            let deploy_transaction = BroadcastedTransaction::Deploy(BroadcastedDeployTransaction {
                version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                contract_address_salt: ContractAddressSalt(starkhash!("deadbeef")),
                constructor_calldata: vec![],
                contract_class: CONTRACT_CLASS.clone(),
            });

            let input = EstimateFeeInput {
                request: deploy_transaction,
                block_id: BLOCK_5,
            };
            let result = estimate_fee(context, input).await.unwrap();
            assert_eq!(
                result,
                FeeEstimate {
                    gas_consumed: Default::default(),
                    gas_price: Default::default(),
                    overall_fee: Default::default()
                }
            );
        }
    }
}
