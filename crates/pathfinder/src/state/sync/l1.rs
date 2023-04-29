use pathfinder_ethereum::{EthereumClientApi, L1StateUpdate};
use tokio::sync::mpsc::Sender;

/// Syncs L1 state updates.
pub async fn sync(
    tx_event: Sender<L1StateUpdate>,
    ethereum_client: impl EthereumClientApi,
    poll_interval: std::time::Duration,
) {
    let mut backoff = ExpBackoffDelay::new(std::time::Duration::from_secs(1), poll_interval);
    loop {
        tokio::time::sleep(backoff.delay()).await;

        match ethereum_client.get_starknet_state().await {
            Ok(state) => {
                backoff.success();
                if let Err(e) = tx_event.send(state).await {
                    tracing::error!(reason=?e, "L1 update failed");
                }
            }
            Err(e) => {
                backoff.failure();
                tracing::debug!(reason=?e, "L1 call failed");
            }
        }
    }
}

pub struct ExpBackoffDelay {
    ok: bool,
    min: std::time::Duration,
    max: std::time::Duration,
    delay: std::time::Duration,
}

impl ExpBackoffDelay {
    pub fn new(min: std::time::Duration, max: std::time::Duration) -> Self {
        Self {
            ok: true,
            min,
            max,
            delay: max,
        }
    }

    pub fn success(&mut self) {
        self.delay = self.max;
        self.ok = true;
    }

    pub fn failure(&mut self) {
        if self.ok {
            self.delay = self.min;
        } else {
            self.delay *= 2;
        }
        if self.delay > self.max {
            self.delay = self.max;
        }
        self.ok = false;
    }

    pub fn delay(&self) -> std::time::Duration {
        self.delay
    }

    pub fn min(&self) -> std::time::Duration {
        self.min
    }

    pub fn max(&self) -> std::time::Duration {
        self.max
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        let min = std::time::Duration::from_secs(1);
        let max = std::time::Duration::from_secs(10);

        let mut backoff = ExpBackoffDelay::new(min, max);
        assert_eq!(backoff.delay(), max);

        backoff.success();
        assert_eq!(backoff.delay(), max);

        backoff.failure();
        assert_eq!(backoff.delay(), min);

        backoff.failure();
        assert_eq!(backoff.delay(), min * 2);

        backoff.failure();
        assert_eq!(backoff.delay(), min * 4);

        backoff.failure();
        assert_eq!(backoff.delay(), min * 8);

        backoff.failure();
        assert_eq!(backoff.delay(), max);

        backoff.failure();
        assert_eq!(backoff.delay(), max);

        backoff.success();
        assert_eq!(backoff.delay(), max);
    }
}
