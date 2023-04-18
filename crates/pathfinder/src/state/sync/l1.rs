use pathfinder_ethereum::{L1StateUpdate, StarknetEthereumClient};
use tokio::sync::mpsc::Sender;

/// Syncs L1 state updates.
pub async fn sync(
    tx_event: Sender<L1StateUpdate>,
    ethereum_client: StarknetEthereumClient,
    start_delay: std::time::Duration,
    poll_interval: std::time::Duration,
) {
    tokio::time::sleep(start_delay).await;

    let mut backoff = RetryBackoff::new(std::time::Duration::from_secs(1), poll_interval);
    loop {
        tokio::time::sleep(backoff.delay()).await;

        match ethereum_client.get_starknet_state().await {
            Ok(state) => {
                backoff.success();
                if let Err(e) = tx_event.send(state).await {
                    tracing::error!(reason=?e, "L1 state update propagation failed");
                }
            }
            Err(e) => {
                backoff.failure();
                tracing::error!(reason=?e, "L1 call failed");
            }
        }
    }
}

struct RetryBackoff {
    ok: bool,
    min_millis: u32,
    max_millis: u32,
    delay_millis: u32,
}

impl RetryBackoff {
    fn new(min: std::time::Duration, max: std::time::Duration) -> Self {
        Self {
            ok: true,
            min_millis: min.as_millis() as u32,
            max_millis: max.as_millis() as u32,
            delay_millis: max.as_millis() as u32,
        }
    }

    fn success(&mut self) {
        self.delay_millis = self.max_millis;
        self.ok = true;
    }

    fn failure(&mut self) {
        if self.ok {
            self.delay_millis = self.min_millis;
        } else {
            self.delay_millis *= 2;
        }
        if self.delay_millis > self.max_millis {
            self.delay_millis = self.max_millis;
        }
        self.ok = false;
    }

    fn delay(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.delay_millis as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff() {
        let min = std::time::Duration::from_secs(1);
        let max = std::time::Duration::from_secs(10);

        let mut backoff = RetryBackoff::new(min, max);
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
