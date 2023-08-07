use std::sync::Arc;

use anyhow::Context;
use primitive_types::U256;
use stark_hash::Felt;
use starknet_api::core::PatriciaKey;

use super::v02::types::request::BroadcastedTransaction;
use pathfinder_common::ChainId;
use pathfinder_common::{BlockId, BlockTimestamp, StateUpdate};
use pathfinder_executor::IntoStarkFelt;
use starknet_gateway_types::pending::PendingData;

use crate::context::RpcContext;

pub enum ExecutionStateError {
    BlockNotFound,
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for ExecutionStateError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

pub(crate) async fn execution_state(
    context: RpcContext,
    block_id: BlockId,
    forced_gas_price: Option<U256>,
) -> Result<pathfinder_executor::ExecutionState, ExecutionStateError> {
    let (gas_price, at_block, pending_timestamp, pending_update) =
        prepare_block(&context, block_id, forced_gas_price).await?;

    let storage = context.storage.clone();
    let span = tracing::Span::current();

    let block = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction().context("Creating database transaction")?;

        let block = tx
            .block_header(at_block)
            .context("Reading block")?
            .ok_or_else(|| ExecutionStateError::BlockNotFound)?;

        Ok::<_, ExecutionStateError>(block)
    })
    .await
    .context("Getting block")??;

    let gas_price = match gas_price {
        GasPriceSource::PastBlock => block.gas_price.0.into(),
        GasPriceSource::Current(c) => c,
    };

    let timestamp = pending_timestamp.unwrap_or(block.timestamp);

    let connection = context.storage.connection()?;

    let execution_state = pathfinder_executor::ExecutionState {
        connection,
        chain_id: context.chain_id,
        block_number: block.number,
        block_timestamp: timestamp,
        sequencer_address: block.sequencer_address,
        state_at_block: Some(block.number),
        gas_price,
        pending_update,
    };

    Ok(execution_state)
}

async fn prepare_block(
    context: &RpcContext,
    block_id: BlockId,
    forced_gas_price: Option<U256>,
) -> anyhow::Result<(
    GasPriceSource,
    pathfinder_storage::BlockId,
    Option<BlockTimestamp>,
    Option<Arc<StateUpdate>>,
)> {
    let gas_price = match forced_gas_price {
        Some(forced_gas_price) => GasPriceSource::Current(forced_gas_price),
        None => {
            // discussed during estimateFee work: when user is requesting using block_hash use the
            // gasPrice from the starknet_blocks::gas_price column, otherwise (tags) get the latest
            // eth_gasPrice.
            //
            // the fact that [`base_block_and_pending_for_call`] transforms pending cases to use
            // actual parent blocks by hash is an internal transformation we do for correctness,
            // unrelated to this consideration.
            if matches!(block_id, BlockId::Pending | BlockId::Latest) {
                let gas_price = match context.eth_gas_price.as_ref() {
                    Some(cached) => cached.get().await,
                    None => None,
                };

                let gas_price = gas_price
                    .ok_or_else(|| anyhow::anyhow!("Current eth_gasPrice is unavailable"))?;

                GasPriceSource::Current(gas_price)
            } else {
                GasPriceSource::PastBlock
            }
        }
    };

    let (when, pending_timestamp, pending_update) =
        base_block_and_pending_for_call(block_id, &context.pending_data).await?;

    Ok((gas_price, when, pending_timestamp, pending_update))
}

/// Where should the call code get the used `BlockInfo::gas_price`
pub enum GasPriceSource {
    /// Use gasPrice recorded on the `starknet_blocks::gas_price`.
    ///
    /// This is not implied by other arguments such as `at_block` because we might need to
    /// manufacture a block hash for some future use cases.
    PastBlock,
    /// Use this latest value from `eth_gasPrice`.
    Current(primitive_types::U256),
}

/// Transforms the request to call or estimate fee at some point in time to the type expected
/// by [`pathfinder_executor`] with the optional, latest pending data.
async fn base_block_and_pending_for_call(
    at_block: BlockId,
    pending_data: &Option<PendingData>,
) -> Result<
    (
        pathfinder_storage::BlockId,
        Option<BlockTimestamp>,
        Option<Arc<StateUpdate>>,
    ),
    anyhow::Error,
> {
    match at_block {
        BlockId::Number(n) => Ok((n.into(), None, None)),
        BlockId::Hash(h) => Ok((h.into(), None, None)),
        BlockId::Latest => Ok((pathfinder_storage::BlockId::Latest, None, None)),
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
                        pathfinder_storage::BlockId::Latest,
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

pub(crate) fn map_broadcasted_transaction(
    transaction: &BroadcastedTransaction,
    chain_id: ChainId,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    match transaction {
        BroadcastedTransaction::Declare(tx) => match tx {
            crate::v02::types::request::BroadcastedDeclareTransaction::V0(tx) => {
                let class_hash = tx.contract_class.class_hash()?.hash();

                let transaction_hash = transaction.transaction_hash(chain_id, Some(class_hash));

                let contract_class_json = tx
                    .contract_class
                    .serialize_to_json()
                    .context("Serializing Cairo class to JSON")?;

                let contract_class =
                    pathfinder_executor::parse_deprecated_class_definition(contract_class_json)?;

                let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                    transaction_hash: starknet_api::transaction::TransactionHash(
                        transaction_hash.0.into_starkfelt(),
                    ),
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    nonce: starknet_api::core::Nonce(Felt::ZERO.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(class_hash.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Declare(
                        starknet_api::transaction::DeclareTransaction::V0(tx),
                    ),
                    Some(contract_class),
                    None,
                )?;
                Ok(tx)
            }
            crate::v02::types::request::BroadcastedDeclareTransaction::V1(tx) => {
                let class_hash = tx.contract_class.class_hash()?.hash();

                let transaction_hash = transaction.transaction_hash(chain_id, Some(class_hash));

                let contract_class_json = tx
                    .contract_class
                    .serialize_to_json()
                    .context("Serializing Cairo class to JSON")?;

                let contract_class =
                    pathfinder_executor::parse_deprecated_class_definition(contract_class_json)?;

                let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                    transaction_hash: starknet_api::transaction::TransactionHash(
                        transaction_hash.0.into_starkfelt(),
                    ),
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(class_hash.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Declare(
                        starknet_api::transaction::DeclareTransaction::V0(tx),
                    ),
                    Some(contract_class),
                    None,
                )?;
                Ok(tx)
            }
            crate::v02::types::request::BroadcastedDeclareTransaction::V2(tx) => {
                let sierra_class_hash = tx.contract_class.class_hash()?.hash();

                let transaction_hash =
                    transaction.transaction_hash(chain_id, Some(sierra_class_hash));

                let casm_contract_definition =
                    pathfinder_compiler::compile_to_casm_with_latest_compiler(
                        &tx.contract_class
                            .serialize_to_json()
                            .context("Serializing Sierra class definition")?,
                    )
                    .context("Compiling Sierra class definition to CASM")?;

                let casm_contract_definition =
                    pathfinder_executor::parse_casm_definition(casm_contract_definition)
                        .context("Parsing CASM contract definition")?;

                let tx = starknet_api::transaction::DeclareTransactionV2 {
                    transaction_hash: starknet_api::transaction::TransactionHash(
                        transaction_hash.0.into_starkfelt(),
                    ),
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(sierra_class_hash.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                    compiled_class_hash: starknet_api::core::CompiledClassHash(
                        tx.compiled_class_hash.0.into_starkfelt(),
                    ),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Declare(
                        starknet_api::transaction::DeclareTransaction::V2(tx),
                    ),
                    Some(casm_contract_definition),
                    None,
                )?;

                Ok(tx)
            }
        },
        BroadcastedTransaction::Invoke(tx) => match tx {
            crate::v02::types::request::BroadcastedInvokeTransaction::V1(tx) => {
                let transaction_hash = transaction.transaction_hash(chain_id, None);

                let tx = starknet_api::transaction::InvokeTransactionV1 {
                    transaction_hash: starknet_api::transaction::TransactionHash(
                        transaction_hash.0.into_starkfelt(),
                    ),
                    // TODO: maybe we should store tx.max_fee as u128 internally?
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                    calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                        tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                    )),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Invoke(
                        starknet_api::transaction::InvokeTransaction::V1(tx),
                    ),
                    None,
                    None,
                )?;

                Ok(tx)
            }
        },
        BroadcastedTransaction::DeployAccount(tx) => {
            let transaction_hash = transaction.transaction_hash(chain_id, None);

            let deployed_contract_address = tx.deployed_contract_address();

            let tx = starknet_api::transaction::DeployAccountTransaction {
                transaction_hash: starknet_api::transaction::TransactionHash(
                    transaction_hash.0.into_starkfelt(),
                ),
                contract_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(deployed_contract_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                ),
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                version: starknet_api::transaction::TransactionVersion(
                    tx.version.without_query_version().into(),
                ),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),

                contract_address_salt: starknet_api::transaction::ContractAddressSalt(
                    tx.contract_address_salt.0.into_starkfelt(),
                ),
                constructor_calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.constructor_calldata
                        .iter()
                        .map(|c| c.0.into_starkfelt())
                        .collect(),
                )),
            };

            let tx = pathfinder_executor::Transaction::from_api(
                starknet_api::transaction::Transaction::DeployAccount(tx),
                None,
                None,
            )?;

            Ok(tx)
        }
    }
}
