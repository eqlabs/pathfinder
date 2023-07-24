use std::sync::Arc;
use std::time::Duration;

use starknet_gateway_client::GatewayApi;

/// Caching of starknet's gas price with single request at a time refreshing.
///
/// The `gasPrice` is used for `estimate_fee` when user
/// requests for [`pathfinder_common::BlockId::Latest`] or  [`pathfinder_common::BlockId::Pending`].
#[derive(Clone)]
pub struct Cached {
    inner: Arc<std::sync::Mutex<Inner>>,
    gateway: starknet_gateway_client::Client,
    stale_limit: Duration,
}

impl Cached {
    pub fn new(gateway: starknet_gateway_client::Client) -> Self {
        Cached {
            inner: Default::default(),
            gateway,
            stale_limit: Duration::from_secs(60),
        }
    }

    /// Returns either a fast fresh value, slower a periodically polled value or fails because
    /// polling has stopped.
    pub async fn get(&self) -> Option<primitive_types::U256> {
        let mut rx = {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());

            if let Some((fetched_at, gas_price)) = g.latest.as_ref() {
                if fetched_at.elapsed() < self.stale_limit {
                    // fresh
                    let accepted = *gas_price;
                    return Some(accepted);
                }
            }

            // clear stale since it's not going to be useful for anyone
            g.latest = None;

            // this is an adaptation of https://fasterthanli.me/articles/request-coalescing-in-async-rust

            if let Some(tx) = g.next.upgrade() {
                // there's already an existing request being fulfilled
                tx.subscribe()
            } else {
                let (tx, rx) = tokio::sync::broadcast::channel(1);

                // the use of Weak works here, because the only strong reference is being sent to
                // the async task, which upon completion holds the lock again while sending
                // everyone listening the response, and clears the weak.
                let tx = Arc::new(tx);

                let inner = self.inner.clone();
                let gateway = self.gateway.clone();

                g.next = Arc::downgrade(&tx);

                // Update the gas price from the starknet pending block.
                tokio::spawn(async move {
                    use starknet_gateway_types::reply::MaybePendingBlock;
                    let gas_price = match gateway
                        // Don't indefinitely retry as this could block the RPC request.
                        .block_without_retry(pathfinder_common::BlockId::Pending)
                        .await
                    {
                        Ok(b) => match b {
                            MaybePendingBlock::Pending(b) => b.gas_price,
                            MaybePendingBlock::Block(b) => match b.gas_price {
                                Some(g) => g,
                                None => {
                                    tracing::debug!("Gas price missing in block");
                                    let _ = tx.send(None);
                                    return;
                                }
                            },
                        },
                        Err(reason) => {
                            tracing::debug!(%reason, "Failed to fetch gas price");
                            let _ = tx.send(None);
                            return;
                        }
                    };

                    let now = std::time::Instant::now();

                    let gas_price = gas_price.0.into();

                    let mut g = inner.lock().unwrap_or_else(|e| e.into_inner());
                    g.latest.replace((now, gas_price));

                    let _ = tx.send(Some(gas_price));
                    drop(tx);
                    // when g is dropped and the mutex unlocked, no one will be able to upgrade
                    // the weak, because the only strong has been dropped.
                });

                rx
            }
        };

        rx.recv().await.ok().flatten()
    }
}

#[derive(Default)]
struct Inner {
    latest: Option<(std::time::Instant, primitive_types::U256)>,
    next: std::sync::Weak<tokio::sync::broadcast::Sender<Option<primitive_types::U256>>>,
}
