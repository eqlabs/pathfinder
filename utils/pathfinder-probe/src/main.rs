use anyhow::Context;
use axum::{routing, Router};
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Url;
use std::{net::SocketAddr, time::Duration};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

// RUST_LOG=pathfinder_probe=debug ./target/release/pathfinder-probe 0.0.0.0:19999 https://alpha-mainnet.starknet.io http://127.0.0.1:9545 5
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("failed to install recorder");

    let setup = setup()?;
    tracing::debug!(setup=?setup, "pathfinder-probe starting");

    let listen_at = setup.listen_at;
    tracing::info!(server=?listen_at, "pathfinder-probe running");

    tokio::spawn(async move {
        loop {
            if let Err(cause) = tick(&setup).await {
                tracing::error!(%cause, "Probe failed");
                metrics::counter!("probe_failed", 1);
            }
            tokio::time::sleep(setup.poll_delay).await;
        }
    });

    let app = Router::new().route("/metrics", routing::get(|| async move { handle.render() }));

    axum::Server::bind(&listen_at)
        .serve(app.into_make_service())
        .await
        .unwrap();

    Ok(())
}

#[derive(Debug)]
struct Setup {
    listen_at: SocketAddr,
    gateway_url: Url,
    pathfinder_url: Url,
    poll_delay: Duration,
}

#[derive(Debug)]
struct Head {
    block_number: i64,
    block_timestamp: i64,
}

fn setup() -> anyhow::Result<Setup> {
    let args = std::env::args().collect::<Vec<String>>();
    args.get(1)
        .zip(args.get(2))
        .zip(args.get(3))
        .zip(args.get(4))
        .map(|(((listen_at, gateway_url), pathfinder_url), delay_seconds)| Ok(Setup {
            listen_at: listen_at.parse().context("Failed to parse <listen-at> socket address")?,
            gateway_url: Url::parse(gateway_url).context("Failed to parse <gateway-url> as URL")?,
            pathfinder_url: Url::parse(pathfinder_url).context("Failed to parse <pathfinder-url> as URL")?,
            poll_delay: Duration::from_secs(delay_seconds.parse().context("Failed to parse <poll-seconds> integer")?),
        }))
        .ok_or(anyhow::anyhow!("Failed to parse arguments: <listen-at> <gateway-url> <pathfinder-url> <poll-delay-seconds>"))?
}

// curl "https://alpha-mainnet.starknet.io/feeder_gateway/get_block?blockNumber=latest" 2>/dev/null | jq '.block_number'
async fn get_gateway_latest(gateway_url: &Url) -> anyhow::Result<Head> {
    let json: serde_json::Value = reqwest::ClientBuilder::new()
        .build()?
        .get(gateway_url.join("feeder_gateway/get_block?blockNumber=latest")?)
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?
        .json()
        .await?;

    let block_number = json["block_number"]
        .as_i64()
        .ok_or(anyhow::anyhow!("Failed to fetch block number"))?;

    let block_timestamp = json["timestamp"]
        .as_i64()
        .ok_or(anyhow::anyhow!("Failed to fetch block timestamp"))?;

    Ok(Head {
        block_number,
        block_timestamp,
    })
}

// curl -H 'Content-type: application/json' -d '{"jsonrpc":"2.0","method":"starknet_getBlockWithTxHashes","params":["latest"],"id":1}' http://127.0.0.1:9000/rpc/v0.3
async fn get_pathfinder_head(pathfinder_url: &Url) -> anyhow::Result<Head> {
    let json: serde_json::Value = reqwest::ClientBuilder::new().build()?
        .post(pathfinder_url.join("rpc/v0.3")?)
        .header("Content-type", "application/json")
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"starknet_getBlockWithTxHashes","params":["latest"],"id":1}))
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?
        .json()
        .await?;

    let block_number = json["result"]
        .as_object()
        .ok_or(anyhow::anyhow!("Response 'result' missing"))?
        ["block_number"]
        .as_i64()
        .ok_or(anyhow::anyhow!("Failed to fetch block number"))?;

    let block_timestamp = json["result"]
        .as_object()
        .ok_or(anyhow::anyhow!("Response 'result' missing"))?
        ["timestamp"]
        .as_i64()
        .ok_or(anyhow::anyhow!("Failed to fetch block timestamp"))?;

    Ok(Head {
        block_number,
        block_timestamp,
    })
}

async fn tick(setup: &Setup) -> anyhow::Result<()> {
    let gw = get_gateway_latest(&setup.gateway_url).await?;
    tracing::debug!(head = gw.block_number, "gateway");

    let pf = get_pathfinder_head(&setup.pathfinder_url).await?;
    tracing::debug!(head = pf.block_number, "pathfinder");

    metrics::gauge!("gw_head", gw.block_number as f64);
    metrics::gauge!("pf_head", pf.block_number as f64);

    let blocks_missing = gw.block_number - pf.block_number;
    metrics::gauge!("blocks_missing", blocks_missing as f64);

    let blocks_delay = gw.block_timestamp - pf.block_timestamp;
    metrics::gauge!("blocks_delay", blocks_delay as f64);

    Ok(())
}
