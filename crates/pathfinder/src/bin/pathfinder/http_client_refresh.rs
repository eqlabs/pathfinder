use starknet_gateway_client::Client;

pub async fn refresh_http_client_periodically(client: Client) -> anyhow::Result<()> {
    loop {
        // Refresh the HTTP client every minute to ensure that we have a fresh
        // connection pool and updated DNS information.
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        refresh_http_client(&client)?;
    }
}

pub fn refresh_http_client(client: &Client) -> anyhow::Result<()> {
    tracing::debug!("Refreshing HTTP client");
    client.refresh()
}
