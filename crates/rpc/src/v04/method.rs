mod add_declare_transaction;
mod add_deploy_account_transaction;
mod add_invoke_transaction;
mod estimate_message_fee;
mod get_transaction_receipt;
mod simulate_transactions;
mod syncing;

pub(super) use add_declare_transaction::add_declare_transaction;
pub(super) use add_deploy_account_transaction::add_deploy_account_transaction;
pub(super) use add_invoke_transaction::add_invoke_transaction;
pub(super) use estimate_message_fee::estimate_message_fee;
pub(super) use get_transaction_receipt::get_transaction_receipt;
pub(super) use simulate_transactions::simulate_transactions;
pub(super) use syncing::syncing;

pub(crate) mod common {
    use std::sync::Arc;

    use pathfinder_common::{BlockId, BlockTimestamp, StateUpdate};
    use starknet_gateway_types::pending::PendingData;

    use crate::{
        cairo::ext_py::{BlockHashNumberOrLatest, GasPriceSource, Handle},
        context::RpcContext,
    };

    pub async fn prepare_handle_and_block(
        context: &RpcContext,
        block_id: BlockId,
    ) -> Result<
        (
            &Handle,
            GasPriceSource,
            BlockHashNumberOrLatest,
            Option<BlockTimestamp>,
            Option<Arc<StateUpdate>>,
        ),
        anyhow::Error,
    > {
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
        let gas_price = if matches!(block_id, BlockId::Pending | BlockId::Latest) {
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
            base_block_and_pending_for_call(block_id, &context.pending_data).await?;

        Ok((handle, gas_price, when, pending_timestamp, pending_update))
    }

    /// Transforms the request to call or estimate fee at some point in time to the type expected
    /// by [`crate::cairo::ext_py`] with the optional, latest pending data.
    pub async fn base_block_and_pending_for_call(
        at_block: BlockId,
        pending_data: &Option<PendingData>,
    ) -> Result<
        (
            BlockHashNumberOrLatest,
            Option<BlockTimestamp>,
            Option<Arc<StateUpdate>>,
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
}
