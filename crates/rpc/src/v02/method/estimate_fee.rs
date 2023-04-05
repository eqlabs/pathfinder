use crate::context::RpcContext;
use crate::v02::types::{reply::FeeEstimate, request::BroadcastedTransaction};
use anyhow::Context;
use ethers::types::U256;
use pathfinder_common::BlockId;
use pathfinder_storage::StarknetBlocksTable;

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateFeeInput {
    request: BroadcastedTransaction,
    block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateFeeError: BlockNotFound,
    ContractNotFound,
    ContractError,
    InvalidMessageSelector,
    InvalidCallData
);

impl From<crate::cairo::starknet_rs::CallError> for EstimateFeeError {
    fn from(value: crate::cairo::starknet_rs::CallError) -> Self {
        use crate::cairo::starknet_rs::CallError::*;
        match value {
            ContractNotFound => Self::ContractNotFound,
            InvalidMessageSelector => Self::InvalidMessageSelector,
            Internal(e) => Self::Internal(e),
        }
    }
}

pub async fn estimate_fee(
    context: RpcContext,
    input: EstimateFeeInput,
) -> Result<FeeEstimate, EstimateFeeError> {
    let (block_id, _pending_timestamp, _pending_update) =
        super::call::base_block_and_pending_for_call(input.block_id, &context.pending_data).await?;

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    // FIXME: handle pending data
    let (storage_commitment, past_gas_price) = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction().context("Creating database transaction")?;

        let storage_commitment = StarknetBlocksTable::get_storage_commitment(&tx, block_id)
            .context("Reading storage root for block")?
            .ok_or_else(|| EstimateFeeError::BlockNotFound)?;

        let past_gas_price = match input.block_id {
            BlockId::Latest | BlockId::Pending => None,
            BlockId::Hash(h) => {
                StarknetBlocksTable::get_gas_price(&tx, h.into())?.map(|p| p.0.into())
            }
            BlockId::Number(n) => {
                StarknetBlocksTable::get_gas_price(&tx, n.into())?.map(|p| p.0.into())
            }
        };

        Ok::<(_, _), EstimateFeeError>((storage_commitment, past_gas_price))
    })
    .await
    .context("Getting storage commitment and gas price")??;

    let gas_price = match past_gas_price {
        Some(gas_price) => gas_price,
        None => current_gas_price(&context.eth_gas_price).await?,
    };

    // FIXME: run as a blocking task
    let mut result = crate::cairo::starknet_rs::estimate_fee(
        context.storage,
        storage_commitment,
        vec![input.request],
        context.chain_id,
        gas_price,
    )?;

    if result.len() != 1 {
        return Err(
            anyhow::anyhow!("Internal error: expected exactly one fee estimation result").into(),
        );
    }

    let result = result.pop().unwrap();

    Ok(FeeEstimate {
        gas_consumed: result.gas_consumed.into(),
        gas_price: result.gas_price.into(),
        overall_fee: result.overall_fee,
    })
}

async fn current_gas_price(
    eth_gas_price: &Option<crate::gas_price::Cached>,
) -> Result<U256, anyhow::Error> {
    let gas_price = match eth_gas_price {
        Some(cached) => cached.get().await,
        None => None,
    };

    gas_price.ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v02::types::request::BroadcastedInvokeTransaction;
    use pathfinder_common::{
        felt, CallParam, Chain, ContractAddress, EntryPoint, Fee, StarknetBlockHash,
        TransactionNonce, TransactionSignatureElem, TransactionVersion,
    };
    use pathfinder_storage::JournalMode;
    use std::path::PathBuf;

    mod parsing {
        use super::*;

        fn test_invoke_txn() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                crate::v02::types::request::BroadcastedInvokeTransactionV0 {
                    version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                    max_fee: Fee(ethers::types::H128::from_low_u64_be(0x6)),
                    signature: vec![TransactionSignatureElem(felt!("0x7"))],
                    nonce: Some(TransactionNonce(felt!("0x8"))),
                    contract_address: ContractAddress::new_or_panic(felt!("0xaaa")),
                    entry_point_selector: EntryPoint(felt!("0xe")),
                    calldata: vec![CallParam(felt!("0xff"))],
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
                block_id: BlockId::Hash(StarknetBlockHash(felt!("0xabcde"))),
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
                block_id: BlockId::Hash(StarknetBlockHash(felt!("0xabcde"))),
            };
            assert_eq!(input, expected);
        }
    }

    // These tests require a Python environment properly set up _and_ a mainnet database with the first six blocks.
    mod ext_py {
        use std::sync::Arc;

        use super::*;
        use crate::v02::types::request::{
            BroadcastedDeclareTransaction, BroadcastedDeclareTransactionV0V1,
            BroadcastedInvokeTransactionV0,
        };
        use crate::v02::types::{CairoContractClass, ContractClass};
        use pathfinder_common::{felt_bytes, StarknetBlockNumber};

        // Mainnet block number 5
        const BLOCK_5: BlockId = BlockId::Hash(StarknetBlockHash(felt!(
            "00dcbd2a4b597d051073f40a0329e585bb94b26d73df69f8d72798924fd097d3"
        )));

        // Data from transaction 0xc52079f33dcb44a58904fac3803fd908ac28d6632b67179ee06f2daccb4b5.
        fn valid_mainnet_invoke_v0() -> BroadcastedInvokeTransactionV0 {
            BroadcastedInvokeTransactionV0 {
                version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                max_fee: Fee(ethers::types::H128::from_low_u64_be(10_000_000_000_000_000)),
                signature: vec![],
                nonce: Some(TransactionNonce(Default::default())),
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

        fn valid_broadcasted_transaction() -> BroadcastedTransaction {
            BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                valid_mainnet_invoke_v0(),
            ))
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
            let context = RpcContext::new(storage, sync_state, ChainId::MAINNET, sequencer);
            context
        }

        #[tokio::test]
        async fn no_such_block() {
            let context = test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: valid_broadcasted_transaction(),
                block_id: BlockId::Hash(StarknetBlockHash(felt_bytes!(b"nonexistent"))),
            };
            let error = estimate_fee(context, input).await;
            assert_matches::assert_matches!(error, Err(EstimateFeeError::BlockNotFound));
        }

        #[tokio::test]
        async fn no_such_contract() {
            let context = test_context_with_call_handling().await;

            let mainnet_invoke = valid_mainnet_invoke_v0();
            let input = EstimateFeeInput {
                request: BroadcastedTransaction::Invoke(BroadcastedInvokeTransaction::V0(
                    BroadcastedInvokeTransactionV0 {
                        contract_address: ContractAddress::new_or_panic(felt!("0xdeadbeef")),
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
            let context = test_context_with_call_handling().await;

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
            let context = test_context_with_call_handling().await;

            let input = EstimateFeeInput {
                request: valid_broadcasted_transaction(),
                block_id: BlockId::Number(StarknetBlockNumber::new_or_panic(31000)),
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
            pub static ref CONTRACT_CLASS: CairoContractClass = {
                let compressed_json = starknet_gateway_test_fixtures::zstd_compressed_contracts::CONTRACT_DEFINITION;
                let json = zstd::decode_all(compressed_json).unwrap();
                ContractClass::from_definition_bytes(&json).unwrap().as_cairo().unwrap()
            };
        }

        #[test_log::test(tokio::test)]
        async fn successful_declare_v0() {
            let context = test_context_with_call_handling().await;

            let declare_transaction = BroadcastedTransaction::Declare(
                BroadcastedDeclareTransaction::V0V1(BroadcastedDeclareTransactionV0V1 {
                    version: TransactionVersion::ZERO_WITH_QUERY_VERSION,
                    max_fee: Fee(Default::default()),
                    signature: vec![],
                    nonce: TransactionNonce(Default::default()),
                    contract_class: CONTRACT_CLASS.clone(),
                    sender_address: ContractAddress::new_or_panic(felt!("01")),
                }),
            );

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
    }
}
