use std::sync::Arc;

use anyhow::Context;
use pathfinder_common::{
    felt, BlockId, CallParam, ChainId, ContractAddress, EntryPoint, EthereumAddress,
    TransactionHash, TransactionNonce, TransactionVersion,
};
use pathfinder_crypto::Felt;
use pathfinder_executor::{ExecutionState, IntoStarkFelt};
use starknet_api::core::PatriciaKey;

use crate::{context::RpcContext, error::ApplicationError, v06::method::estimate_fee::FeeEstimate};

#[derive(Debug)]
pub enum EstimateMessageFeeError {
    Internal(anyhow::Error),
    BlockNotFound,
    ContractNotFound,
    ContractErrorV05 { revert_error: String },
    Custom(anyhow::Error),
}

impl From<anyhow::Error> for EstimateMessageFeeError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<pathfinder_executor::TransactionExecutionError> for EstimateMessageFeeError {
    fn from(c: pathfinder_executor::TransactionExecutionError) -> Self {
        use pathfinder_executor::TransactionExecutionError::*;
        match c {
            ExecutionError { error, .. } => Self::ContractErrorV05 {
                revert_error: format!("Execution error: {}", error),
            },
            Internal(e) => Self::Internal(e),
            Custom(e) => Self::Custom(e),
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

impl From<EstimateMessageFeeError> for ApplicationError {
    fn from(value: EstimateMessageFeeError) -> Self {
        match value {
            EstimateMessageFeeError::BlockNotFound => ApplicationError::BlockNotFound,
            EstimateMessageFeeError::ContractNotFound => ApplicationError::ContractNotFound,
            EstimateMessageFeeError::ContractErrorV05 { revert_error } => {
                ApplicationError::ContractErrorV05 { revert_error }
            }
            EstimateMessageFeeError::Internal(e) => ApplicationError::Internal(e),
            EstimateMessageFeeError::Custom(e) => ApplicationError::Custom(e),
        }
    }
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EstimateMessageFeeInput {
    pub message: MsgFromL1,
    pub block_id: BlockId,
}

#[derive(serde::Deserialize, Debug, PartialEq, Eq)]
pub struct MsgFromL1 {
    pub from_address: EthereumAddress,
    pub to_address: ContractAddress,
    pub entry_point_selector: EntryPoint,
    pub payload: Vec<CallParam>,
}

pub async fn estimate_message_fee(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<FeeEstimate, EstimateMessageFeeError> {
    let result = estimate_message_fee_impl(context, input).await?;

    Ok(FeeEstimate {
        gas_consumed: result.gas_consumed,
        gas_price: result.gas_price,
        overall_fee: result.overall_fee,
        unit: result.unit.into(),
    })
}

pub(crate) async fn estimate_message_fee_impl(
    context: RpcContext,
    input: EstimateMessageFeeInput,
) -> Result<pathfinder_executor::types::FeeEstimate, EstimateMessageFeeError> {
    let span = tracing::Span::current();

    let mut result = tokio::task::spawn_blocking(move || {
        let _g = span.enter();
        let mut db = context
            .storage
            .connection()
            .context("Creating database connection")?;
        let db = db.transaction().context("Creating database transaction")?;

        let (header, pending) = match input.block_id {
            BlockId::Pending => {
                let pending = context
                    .pending_data
                    .get(&db)
                    .context("Querying pending data")?;

                (pending.header(), Some(pending.state_update.clone()))
            }
            other => {
                let block_id = other.try_into().expect("Only pending cast should fail");
                let header = db
                    .block_header(block_id)
                    .context("Querying block header")?
                    .ok_or(EstimateMessageFeeError::BlockNotFound)?;

                (header, None)
            }
        };

        if !db.contract_exists(input.message.to_address, header.number.into())? {
            return Err(EstimateMessageFeeError::ContractNotFound);
        }

        let state = ExecutionState::simulation(&db, context.chain_id, header, pending);

        let transaction = create_executor_transaction(input, context.chain_id)?;

        let result = pathfinder_executor::estimate(state, vec![transaction], false)?;

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

    Ok(result)
}

fn create_executor_transaction(
    input: EstimateMessageFeeInput,
    chain_id: ChainId,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    let transaction_hash = calculate_transaction_hash(&input, chain_id);

    // prepend sender address to calldata
    let sender_address = Felt::from_be_slice(input.message.from_address.0.as_bytes())
        .expect("Ethereum address is 160 bits");
    let calldata = std::iter::once(pathfinder_common::CallParam(sender_address))
        .chain(input.message.payload)
        .map(|p| p.0.into_starkfelt())
        .collect();

    let tx = starknet_api::transaction::L1HandlerTransaction {
        version: starknet_api::transaction::TransactionVersion(felt!("0x1").into_starkfelt()),
        nonce: starknet_api::core::Nonce(Felt::ZERO.into_starkfelt()),
        contract_address: starknet_api::core::ContractAddress(
            PatriciaKey::try_from(input.message.to_address.0.into_starkfelt())
                .expect("A ContractAddress should be the right size"),
        ),
        entry_point_selector: starknet_api::core::EntryPointSelector(
            input.message.entry_point_selector.0.into_starkfelt(),
        ),
        calldata: starknet_api::transaction::Calldata(Arc::new(calldata)),
    };

    let transaction = pathfinder_executor::Transaction::from_api(
        starknet_api::transaction::Transaction::L1Handler(tx),
        starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
        None,
        Some(starknet_api::transaction::Fee(1)),
        None,
        false,
    )?;
    Ok(transaction)
}

fn calculate_transaction_hash(
    input: &EstimateMessageFeeInput,
    chain_id: ChainId,
) -> TransactionHash {
    let call_params_hash = {
        let mut hh = pathfinder_crypto::hash::HashChain::default();
        hh = input.message.payload.iter().fold(hh, |mut hh, call_param| {
            hh.update(call_param.0);
            hh
        });
        hh.finalize()
    };

    starknet_gateway_types::transaction_hash::compute_txn_hash(
        b"l1_handler",
        TransactionVersion::ONE,
        input.message.to_address,
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
    use serde::Deserialize;
    use starknet_gateway_test_fixtures::class_definitions::{
        CAIRO_1_1_0_BALANCE_CASM_JSON, CAIRO_1_1_0_BALANCE_SIERRA_JSON,
    };
    use tempfile::tempdir;

    use crate::v06::types::PriceUnit;

    use super::*;

    #[test]
    fn test_parse_input_named() {
        let input_json = serde_json::json!({
            "message": {
                "to_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "payload": ["0x1", "0x2"],
                "from_address": "0x0000000000000000000000000000000000000000"
            },
            "block_id": {"block_number": 1},
        });
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: MsgFromL1 {
                    to_address: contract_address!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    ),
                    entry_point_selector: entry_point!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    ),
                    payload: vec![call_param!("0x1"), call_param!("0x2"),],
                    from_address: EthereumAddress(H160::zero()),
                },
                block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
            }
        );
    }

    #[test]
    fn test_parse_input_positional() {
        let input_json = serde_json::json!([
            {
                "to_address": "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
                "entry_point_selector": "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01",
                "payload": ["0x1", "0x2"],
                "from_address": "0x0000000000000000000000000000000000000000"
            },
            {"block_number": 1},
        ]);
        let input = EstimateMessageFeeInput::deserialize(&input_json).unwrap();

        assert_eq!(
            input,
            EstimateMessageFeeInput {
                message: MsgFromL1 {
                    to_address: contract_address!(
                        "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                    ),
                    entry_point_selector: entry_point!(
                        "0xc73f681176fc7b3f9693986fd7b14581e8d540519e27400e88b8713932be01"
                    ),
                    payload: vec![call_param!("0x1"), call_param!("0x2"),],
                    from_address: EthereumAddress(H160::zero()),
                },
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

        let storage = Storage::migrate(db_path, JournalMode::WAL, 1)
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
                    .with_eth_l1_gas_price(GasPrice(1))
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
            message: MsgFromL1 {
                to_address: contract_address!(
                    "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374"
                ),
                entry_point_selector: entry_point!(
                    "0x31ee153a27e249dc4bade6b861b37ef1e1ea0a4c0bf73b7405a02e9e72f7be3"
                ),
                payload: vec![call_param!("0x1")],
                from_address: EthereumAddress(H160::zero()),
            },
            block_id: BlockId::Number(BlockNumber::new_or_panic(1)),
        }
    }

    #[tokio::test]
    async fn test_estimate_message_fee() {
        let expected = FeeEstimate {
            gas_consumed: 16302.into(),
            gas_price: 1.into(),
            overall_fee: 16302.into(),
            unit: PriceUnit::Wei,
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
            Err(EstimateMessageFeeError::ContractErrorV05 { .. })
        );
    }
}
