use std::sync::Arc;
use std::time::{Duration, Instant};

use primitive_types::U256;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::reply::MaybePendingBlock;

/// Caching of starknet's gas price with single request at a time refreshing.
///
/// The `gasPrice` is used for `estimate_fee` when user
/// requests for [`pathfinder_common::BlockId::Latest`] or  [`pathfinder_common::BlockId::Pending`].
#[derive(Clone)]
pub struct Cached {
    value: Arc<std::sync::Mutex<Option<Value>>>,
    gateway: starknet_gateway_client::Client,
    horizon: Duration,
}

#[derive(Clone)]
struct Value {
    gas_price: U256,
    updated: Instant,
}

impl Cached {
    pub fn new(gateway: starknet_gateway_client::Client) -> Self {
        Cached {
            value: Default::default(),
            gateway,
            horizon: Duration::from_secs(60),
        }
    }

    /// Returns either a fast fresh value, slower a periodically polled value or fails because
    /// polling has stopped.
    pub async fn get(&self) -> Option<U256> {
        match self.value.try_lock() {
            Ok(guard) => match *guard {
                Some(Value { gas_price, updated }) if updated.elapsed() < self.horizon => {
                    tracing::debug!(from=?updated, "Using cached gas price value");
                    return Some(gas_price);
                }
                _ => {
                    tracing::debug!("Gas price missing or expired");
                }
            },
            Err(reason) => {
                tracing::debug!(%reason, "Failed to lock gas price mutex");
            }
        }

        if let Some(gas_price) = self.gas_price().await {
            match self.value.try_lock() {
                Ok(ref mut guard) => {
                    **guard = Some(Value {
                        gas_price,
                        updated: Instant::now(),
                    });
                    tracing::debug!(?gas_price, "Cached gas price value updated");
                    return Some(gas_price);
                }
                Err(reason) => {
                    tracing::debug!(%reason, "Failed to lock gas price mutex");
                }
            }
        }

        None
    }

    async fn gas_price(&self) -> Option<U256> {
        match self
            .gateway
            // Don't indefinitely retry as this could block the RPC request.
            .block_without_retry(pathfinder_common::BlockId::Pending)
            .await
        {
            Ok(block) => match block {
                MaybePendingBlock::Pending(block) => {
                    return Some(U256::from(block.gas_price.0));
                }
                MaybePendingBlock::Block(block) => {
                    return block.gas_price.map(|gp| U256::from(gp.0));
                }
            },
            Err(reason) => {
                tracing::debug!(%reason, "Failed to fetch gas price");
            }
        };

        None
    }
}
