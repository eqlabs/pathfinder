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
                let gas_price = context
                    .eth_gas_price
                    .get()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("Current gas price is unavailable"))?;
                GasPriceSource::Current(gas_price)
            } else {
                GasPriceSource::PastBlock
            }
        }
    };

    let storage = context.execution_storage.clone();
    let span = tracing::Span::current();

    let (block, pending_timestamp, pending_update) = tokio::task::spawn_blocking(move || {
        let _g = span.enter();

        let mut db = storage.connection()?;
        let tx = db.transaction().context("Creating database transaction")?;

        let (pending_timestamp, pending_update) = if block_id.is_pending() {
            let pending = context
                .pending_data
                .get(&tx)
                .context("Querying pending data")?;

            (
                Some(pending.block.timestamp),
                Some(pending.state_update.clone()),
            )
        } else {
            (None, None)
        };

        let at_block = match block_id {
            BlockId::Number(x) => x.into(),
            BlockId::Hash(x) => x.into(),
            BlockId::Latest => pathfinder_storage::BlockId::Latest,
            BlockId::Pending => pathfinder_storage::BlockId::Latest,
        };

        let block = tx
            .block_header(at_block)
            .context("Reading block")?
            .ok_or_else(|| ExecutionStateError::BlockNotFound)?;

        Ok::<_, ExecutionStateError>((block, pending_timestamp, pending_update))
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
                    starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
                    Some(contract_class),
                    None,
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
                        starknet_api::transaction::DeclareTransaction::V1(tx),
                    ),
                    starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
                    Some(contract_class),
                    None,
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
                    starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
                    Some(casm_contract_definition),
                    None,
                    None,
                )?;

                Ok(tx)
            }
        },
        BroadcastedTransaction::Invoke(tx) => match tx {
            crate::v02::types::request::BroadcastedInvokeTransaction::V0(tx) => {
                let transaction_hash = transaction.transaction_hash(chain_id, None);

                let tx = starknet_api::transaction::InvokeTransactionV0 {
                    // TODO: maybe we should store tx.max_fee as u128 internally?
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature.iter().map(|s| s.0.into_starkfelt()).collect(),
                    ),
                    contract_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                    entry_point_selector: starknet_api::core::EntryPointSelector(
                        tx.entry_point_selector.0.into_starkfelt(),
                    ),
                    calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                        tx.calldata.iter().map(|c| c.0.into_starkfelt()).collect(),
                    )),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Invoke(
                        starknet_api::transaction::InvokeTransaction::V0(tx),
                    ),
                    starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
                    None,
                    None,
                    None,
                )?;

                Ok(tx)
            }
            crate::v02::types::request::BroadcastedInvokeTransaction::V1(tx) => {
                let transaction_hash = transaction.transaction_hash(chain_id, None);

                let tx = starknet_api::transaction::InvokeTransactionV1 {
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
                    starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
                    None,
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
                starknet_api::transaction::TransactionHash(transaction_hash.0.into_starkfelt()),
                None,
                None,
                Some(starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(deployed_contract_address.get().into_starkfelt())
                        .expect("No sender address overflow expected"),
                )),
            )?;

            Ok(tx)
        }
    }
}

/// Build the executor transaction out of the gateway one
/// while pulling necessary data from the DB along the way.
pub fn compose_executor_transaction(
    transaction: starknet_gateway_types::reply::transaction::Transaction,
    db_transaction: &pathfinder_storage::Transaction<'_>,
) -> anyhow::Result<pathfinder_executor::Transaction> {
    use starknet_api::hash::StarkFelt;

    let tx_hash = starknet_api::transaction::TransactionHash(transaction.hash().0.into_starkfelt());

    tracing::trace!(%tx_hash, "Converting transaction");

    match transaction {
        starknet_gateway_types::reply::transaction::Transaction::Declare(tx) => match tx {
            starknet_gateway_types::reply::transaction::DeclareTransaction::V0(tx) => {
                let class_definition = db_transaction
                    .class_definition(tx.class_hash)?
                    .context("Fetching class definition")?;

                let contract_class =
                    pathfinder_executor::parse_deprecated_class_definition(class_definition)?;

                let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature
                            .into_iter()
                            .map(|s| s.0.into_starkfelt())
                            .collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Declare(
                        starknet_api::transaction::DeclareTransaction::V0(tx),
                    ),
                    tx_hash,
                    Some(contract_class),
                    None,
                    None,
                )?;

                Ok(tx)
            }
            starknet_gateway_types::reply::transaction::DeclareTransaction::V1(tx) => {
                let class_definition = db_transaction
                    .class_definition(tx.class_hash)?
                    .context("Fetching class definition")?;

                let contract_class =
                    pathfinder_executor::parse_deprecated_class_definition(class_definition)?;

                let tx = starknet_api::transaction::DeclareTransactionV0V1 {
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature
                            .into_iter()
                            .map(|s| s.0.into_starkfelt())
                            .collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Declare(
                        starknet_api::transaction::DeclareTransaction::V1(tx),
                    ),
                    tx_hash,
                    Some(contract_class),
                    None,
                    None,
                )?;

                Ok(tx)
            }
            starknet_gateway_types::reply::transaction::DeclareTransaction::V2(tx) => {
                let casm_definition = db_transaction
                    .casm_definition(tx.class_hash)?
                    .context("Fetching class definition")?;

                let contract_class = pathfinder_executor::parse_casm_definition(casm_definition)?;

                let tx = starknet_api::transaction::DeclareTransactionV2 {
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature
                            .into_iter()
                            .map(|s| s.0.into_starkfelt())
                            .collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),
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
                    tx_hash,
                    Some(contract_class),
                    None,
                    None,
                )?;

                Ok(tx)
            }
        },
        starknet_gateway_types::reply::transaction::Transaction::Deploy(tx) => {
            drop(tx);
            Err(anyhow::anyhow!(
                "Deploy transactions are not yet supported in blockifier"
            ))
        }
        starknet_gateway_types::reply::transaction::Transaction::DeployAccount(tx) => {
            let contract_address = starknet_api::core::ContractAddress(
                PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                    .expect("No contract address overflow expected"),
            );

            let tx = starknet_api::transaction::DeployAccountTransaction {
                max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                    tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                )),
                version: starknet_api::transaction::TransactionVersion(
                    StarkFelt::new(tx.version.0.as_fixed_bytes().to_owned())
                        .expect("No transaction version overflow expected"),
                ),
                signature: starknet_api::transaction::TransactionSignature(
                    tx.signature
                        .into_iter()
                        .map(|s| s.0.into_starkfelt())
                        .collect(),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                class_hash: starknet_api::core::ClassHash(tx.class_hash.0.into_starkfelt()),

                contract_address_salt: starknet_api::transaction::ContractAddressSalt(
                    tx.contract_address_salt.0.into_starkfelt(),
                ),
                constructor_calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.constructor_calldata
                        .into_iter()
                        .map(|c| c.0.into_starkfelt())
                        .collect(),
                )),
            };

            let tx = pathfinder_executor::Transaction::from_api(
                starknet_api::transaction::Transaction::DeployAccount(tx),
                tx_hash,
                None,
                None,
                Some(contract_address),
            )?;

            Ok(tx)
        }
        starknet_gateway_types::reply::transaction::Transaction::Invoke(tx) => match tx {
            starknet_gateway_types::reply::transaction::InvokeTransaction::V0(tx) => {
                let tx = starknet_api::transaction::InvokeTransactionV0 {
                    // TODO: maybe we should store tx.max_fee as u128 internally?
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature
                            .into_iter()
                            .map(|s| s.0.into_starkfelt())
                            .collect(),
                    ),
                    contract_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                    entry_point_selector: starknet_api::core::EntryPointSelector(
                        tx.entry_point_selector.0.into_starkfelt(),
                    ),
                    calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                        tx.calldata
                            .into_iter()
                            .map(|c| c.0.into_starkfelt())
                            .collect(),
                    )),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Invoke(
                        starknet_api::transaction::InvokeTransaction::V0(tx),
                    ),
                    tx_hash,
                    None,
                    None,
                    None,
                )?;

                Ok(tx)
            }
            starknet_gateway_types::reply::transaction::InvokeTransaction::V1(tx) => {
                let tx = starknet_api::transaction::InvokeTransactionV1 {
                    // TODO: maybe we should store tx.max_fee as u128 internally?
                    max_fee: starknet_api::transaction::Fee(u128::from_be_bytes(
                        tx.max_fee.0.to_be_bytes()[16..].try_into().unwrap(),
                    )),
                    signature: starknet_api::transaction::TransactionSignature(
                        tx.signature
                            .into_iter()
                            .map(|s| s.0.into_starkfelt())
                            .collect(),
                    ),
                    nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                    sender_address: starknet_api::core::ContractAddress(
                        PatriciaKey::try_from(tx.sender_address.get().into_starkfelt())
                            .expect("No sender address overflow expected"),
                    ),
                    calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                        tx.calldata
                            .into_iter()
                            .map(|c| c.0.into_starkfelt())
                            .collect(),
                    )),
                };

                let tx = pathfinder_executor::Transaction::from_api(
                    starknet_api::transaction::Transaction::Invoke(
                        starknet_api::transaction::InvokeTransaction::V1(tx),
                    ),
                    tx_hash,
                    None,
                    None,
                    None,
                )?;

                Ok(tx)
            }
        },
        starknet_gateway_types::reply::transaction::Transaction::L1Handler(tx) => {
            let tx = starknet_api::transaction::L1HandlerTransaction {
                version: starknet_api::transaction::TransactionVersion(
                    StarkFelt::new(tx.version.0.as_fixed_bytes().to_owned())
                        .expect("No transaction version overflow expected"),
                ),
                nonce: starknet_api::core::Nonce(tx.nonce.0.into_starkfelt()),
                contract_address: starknet_api::core::ContractAddress(
                    PatriciaKey::try_from(tx.contract_address.get().into_starkfelt())
                        .expect("No contract address overflow expected"),
                ),
                entry_point_selector: starknet_api::core::EntryPointSelector(
                    tx.entry_point_selector.0.into_starkfelt(),
                ),
                calldata: starknet_api::transaction::Calldata(std::sync::Arc::new(
                    tx.calldata
                        .into_iter()
                        .map(|c| c.0.into_starkfelt())
                        .collect(),
                )),
            };

            let tx = pathfinder_executor::Transaction::from_api(
                starknet_api::transaction::Transaction::L1Handler(tx),
                tx_hash,
                None,
                Some(starknet_api::transaction::Fee(1_000_000_000_000)),
                None,
            )?;

            Ok(tx)
        }
    }
}
