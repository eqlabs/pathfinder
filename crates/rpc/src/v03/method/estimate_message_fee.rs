use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{
    felt, BlockId, ChainId, EthereumAddress, TransactionHash, TransactionNonce, TransactionVersion,
};
use pathfinder_executor::IntoStarkFelt;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use stark_hash::Felt;
use starknet_api::core::PatriciaKey;

use crate::{context::RpcContext, v02::method::call::FunctionCall};

#[derive(Deserialize, Debug, PartialEq, Eq)]
pub struct EstimateMessageFeeInput {
    pub message: FunctionCall,
    pub sender_address: EthereumAddress,
    pub block_id: BlockId,
}

crate::error::generate_rpc_error_subset!(
    EstimateMessageFeeError: BlockNotFound,
    ContractNotFound,
    ContractError
);

impl From<pathfinder_executor::CallError> for EstimateMessageFeeError {
    fn from(c: pathfinder_executor::CallError) -> Self {
        use pathfinder_executor::CallError::*;
        match c {
            InvalidMessageSelector => Self::ContractError,
            ContractNotFound => Self::ContractNotFound,
            Reverted(revert_error) => {
                Self::Internal(anyhow::anyhow!("Transaction reverted: {}", revert_error))
            }
            Internal(e) => Self::Internal(e),
        }
    }
}

impl From<crate::executor::ExecutionStateError> for EstimateMessageFeeError {
    fn from(error: crate::executor::ExecutionStateError) -> Self {
        use crate::executor::ExecutionStateError::*;
        match error {
            BlockNotFound => Self::BlockNotFound,
            Internal(e) => Self::Internal(e),
        }
    }
}

#[serde_as]
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FeeEstimate {
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_consumed: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub gas_price: primitive_types::U256,
    #[serde_as(as = "pathfinder_serde::U256AsHexStr")]
    pub overall_fee: primitive_types::U256,
}

pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<FeeEstimate, EstimateMessageFeeError> {
    let chain_id = context.chain_id;
    let execution_state = crate::executor::execution_state(context, input.block_id, None).await?;

    let span = tracing::Span::current();

    let mut result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let transaction = create_executor_transaction(input, chain_id)?;

        let result = pathfinder_executor::estimate(execution_state, vec![transaction])?;

        Ok::<_, EstimateMessageFeeError>(result)
    })
    .await
    .context("Estimating message fee")??;

    if result.len() != 1 {
        return Err(
            anyhow::anyhow!("Internal error: expected exactly one fee estimation result").into(),
        );
    }

    let result = result.pop().unwrap();

    Ok(FeeEstimate {
        gas_consumed: result.gas_consumed,
        gas_price: result.gas_price,
        overall_fee: result.overall_fee,
    })
}

fn create_executor_transaction(
    input: EstimateMessageFeeInput,
    chain_id: ChainId,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    let transaction_hash = calculate_transaction_hash(&input, chain_id);

    // prepend sender address to calldata
    let sender_address = Felt::from_be_slice(input.sender_address.0.as_bytes())
        .expect("Ethereum address is 160 bits");
    let calldata = std::iter::once(pathfinder_common::CallParam(sender_address))
        .chain(input.message.calldata.into_iter())
        .map(|p| p.0.into_starkfelt())
        .collect();

    let tx = starknet_api::transaction::L1HandlerTransaction {
        transaction_hash: starknet_api::transaction::TransactionHash(
            transaction_hash.0.into_starkfelt(),
        ),
        version: starknet_api::transaction::TransactionVersion(felt!("0x1").into_starkfelt()),
        nonce: starknet_api::core::Nonce(Felt::ZERO.into_starkfelt()),
        contract_address: starknet_api::core::ContractAddress(
            PatriciaKey::try_from(input.message.contract_address.0.into_starkfelt())
                .expect("A ContractAddress should be the right size"),
        ),
        entry_point_selector: starknet_api::core::EntryPointSelector(
            input.message.entry_point_selector.0.into_starkfelt(),
        ),
        calldata: starknet_api::transaction::Calldata(Arc::new(calldata)),
    };

    let transaction = pathfinder_executor::Transaction::from_api(
        starknet_api::transaction::Transaction::L1Handler(tx),
        None,
        Some(starknet_api::transaction::Fee(1)),
    )?;
    Ok(transaction)
}

fn calculate_transaction_hash(
    input: &EstimateMessageFeeInput,
    chain_id: ChainId,
) -> TransactionHash {
    let call_params_hash = {
        let mut hh = stark_hash::HashChain::default();
        hh = input
            .message
            .calldata
            .iter()
            .fold(hh, |mut hh, call_param| {
                hh.update(call_param.0);
                hh
            });
        hh.finalize()
    };

    starknet_gateway_types::transaction_hash::compute_txn_hash(
        b"l1_handler",
        TransactionVersion::ONE,
        input.message.contract_address,
        Some(input.message.entry_point_selector),
        call_params_hash,
        None,
        chain_id,
        TransactionNonce::ZERO,
        None,
    )
}

#[cfg(test)]
mod tests {
    use pathfinder_common::macro_prelude::*;
    use pathfinder_common::{
        felt, BlockHash, BlockHeader, BlockNumber, BlockTimestamp, GasPrice, StateUpdate,
    };
    use pathfinder_storage::{JournalMode, Storage};
    use primitive_types::H160;
    use starknet_gateway_test_fixtures::class_definitions::{
        CAIRO_1_1_0_BALANCE_CASM_JSON, CAIRO_1_1_0_BALANCE_SIERRA_JSON,
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_parse_input_named() {
        let input_json = serde_json::json!({
            "message": {
                "contract_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "calldata": ["0x1", "0x2"],
            },
            "sender_address": "0x0000000000000000000000000000000000000000",
            "block_id": {"block_number": 1},
        });
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: FunctionCall {
                    contract_address: contract_address!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    ),
                    entry_point_selector: entry_point!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    ),
                    calldata: vec![call_param!("0x1"), call_param!("0x2"),],
                },
                sender_address: EthereumAddress(H160::zero()),
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    #[test]
    fn test_parse_input_positional() {
        let input_json = serde_json::json!([
            {
                "contract_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "calldata": ["0x1", "0x2"],
            },
            "0x0000000000000000000000000000000000000000",
            {"block_number": 1},
        ]);
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: FunctionCall {
                    contract_address: contract_address!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    ),
                    entry_point_selector: entry_point!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    ),
                    calldata: vec![call_param!("0x1"), call_param!("0x2"),],
                },
                sender_address: EthereumAddress(H160::zero()),
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    enum Setup {
        Full,
        SkipBlock,
        SkipContract,
    }

    async fn setup(mode: Setup) -> anyhow::Result<RpcContext> {
        let dir = tempdir().expect("tempdir");
        let mut db_path = dir.path().to_path_buf();
        db_path.push("db.sqlite");

        let storage = Storage::migrate(db_path, JournalMode::WAL)
            .expect("storage")
            .create_pool(std::num::NonZeroU32::new(1).expect("one"))
            .expect("storage");

        {
            let mut db = storage.connection().expect("db connection");
            let tx = db.transaction().expect("tx");

            let class_hash =
                class_hash!("0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311");
            tx.insert_sierra_class(
                &sierra_hash!("0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311"),
                CAIRO_1_1_0_BALANCE_SIERRA_JSON,
                &casm_hash!("0x0484c163658bcce5f9916f486171ac60143a92897533aa7ff7ac800b16c63311"),
                CAIRO_1_1_0_BALANCE_CASM_JSON,
                "cairo-lang-starknet 1.1.0",
            )
            .expect("insert class");

            let block1_number = BlockNumber::GENESIS + 1;
            let block1_hash = BlockHash(felt!("0xb01"));

            if !matches!(mode, Setup::SkipBlock) {
                let header = BlockHeader::builder()
                    .with_number(BlockNumber::GENESIS)
                    .with_timestamp(BlockTimestamp::new_or_panic(0))
                    .finalize_with_hash(BlockHash(felt!("0xb00")));
                tx.insert_block_header(&header).unwrap();

                let header = BlockHeader::builder()
                    .with_number(block1_number)
                    .with_timestamp(BlockTimestamp::new_or_panic(1))
                    .with_gas_price(GasPrice(1))
                    .finalize_with_hash(block1_hash);
                tx.insert_block_header(&header).unwrap();
            }

            if !matches!(mode, Setup::SkipBlock | Setup::SkipContract) {
                let contract_address = contract_address!(
                    "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                );
                let state_update =
                    StateUpdate::default().with_deployed_contract(contract_address, class_hash);
                tx.insert_state_update(block1_number, &state_update)
                    .unwrap();
            }

            tx.commit().unwrap();
        }

        let rpc = RpcContext::for_tests().with_storage(storage);

        Ok(rpc)
    }

    fn input() -> EstimateMessageFeeInput {
        EstimateMessageFeeInput {
            message: FunctionCall {
                contract_address: contract_address!(
                    "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                ),
                entry_point_selector: entry_point!(
                    "0x31ee153a27e249dc4bade6b861b37ef1e1ea0a4c0bf73b7405a02e9e72f7be3"
                ),
                calldata: vec![call_param!("0x1")],
            },
            sender_address: EthereumAddress(H160::zero()),
            block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
        }
    }

    #[tokio::test]
    async fn test_estimate_message_fee() {
        let expected = FeeEstimate {
            gas_consumed: 17105.into(),
            gas_price: 1.into(),
            overall_fee: 17105.into(),
        };

        let rpc = setup(Setup::Full).await.expect("RPC context");
        let result = estimate_message_fee(rpc, input()).await.expect("result");
        assert_eq!(result, expected);
    }

    #[tokio::test]
    async fn test_error_missing_contract() {
        let rpc = setup(Setup::SkipContract).await.expect("RPC context");
        assert_matches::assert_matches!(
            estimate_message_fee(rpc, input()).await,
            Err(EstimateMessageFeeError::ContractNotFound)
        );
    }

    #[tokio::test]
    async fn test_error_missing_block() {
        let rpc = setup(Setup::SkipBlock).await.expect("RPC context");
        assert_matches::assert_matches!(
            estimate_message_fee(rpc, input()).await,
            Err(EstimateMessageFeeError::BlockNotFound)
        );
    }

    #[tokio::test]
    async fn test_error_invalid_selector() {
        let mut input = input();
        let invalid_selector = entry_point!("0xDEADBEEF");
        input.message.entry_point_selector = invalid_selector;

        let rpc = setup(Setup::Full).await.expect("RPC context");
        assert_matches::assert_matches!(
            estimate_message_fee(rpc, input).await,
            Err(EstimateMessageFeeError::ContractError)
        );
    }
}
