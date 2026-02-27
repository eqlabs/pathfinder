use std::time::Duration;

use starknet_gateway_client::Client;

pub async fn refresh_http_client_periodically(
    client: Client,
    interval: Duration,
) -> anyhow::Result<()> {
    let mut refresh_interval = tokio::time::interval(interval);
    refresh_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        refresh_interval.tick().await;

        // Address resolution using `std::net` is blocking, so we need to run it in a
        // blocking context to avoid blocking the async runtime.
        tokio::task::block_in_place(|| {
            // Ignore the result of refresh since it can fail due to transient network
            // issues, and we don't want to crash the entire application because of that.
            // We'll just try again in the next cycle.
            let _ = client.refresh();
        });
    }
}
