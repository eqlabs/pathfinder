use starknet_gateway_client::Client;

pub async fn refresh_http_client_periodically(client: Client) -> anyhow::Result<()> {
    loop {
        // Refresh the HTTP client every minute to ensure that we have a fresh
        // connection pool and updated DNS information.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        // Ignore the result of refresh since it can fail due to transient network
        // issues, and we don't want to crash the entire application because of that.
        // We'll just try again in the next cycle.
        let _ = client.refresh();
    }
}
