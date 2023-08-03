pub(crate) mod estimate_fee;
pub(crate) mod estimate_message_fee;
mod get_events;
mod get_state_update;
pub(crate) mod simulate_transaction;

pub(crate) use estimate_fee::estimate_fee;
pub(crate) use estimate_message_fee::estimate_message_fee;
pub(crate) use get_events::get_events;
pub(crate) use get_state_update::get_state_update;
pub(crate) use simulate_transaction::simulate_transaction;

pub(crate) mod common {
    use std::sync::Arc;

    use pathfinder_common::{BlockId, BlockTimestamp, StateUpdate};
    use primitive_types::U256;
    use starknet_gateway_types::pending::PendingData;

    use crate::{cairo::starknet_rs::ExecutionState, context::RpcContext};

    use anyhow::Context;

    pub enum ExecutionStateError {
        BlockNotFound,
        Internal(anyhow::Error),
    }

    impl From<anyhow::Error> for ExecutionStateError {
        fn from(error: anyhow::Error) -> Self {
            Self::Internal(error)
        }
    }

    pub async fn execution_state(
        context: RpcContext,
        block_id: BlockId,
        forced_gas_price: Option<U256>,
    ) -> Result<ExecutionState, ExecutionStateError> {
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

        let execution_state = ExecutionState {
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

    pub async fn execution_state_blockifier(
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
    /// by [`crate::cairo::starknet_rs`] with the optional, latest pending data.
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
}
