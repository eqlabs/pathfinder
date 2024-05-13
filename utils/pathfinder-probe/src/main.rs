use anyhow::Context;
use axum::{routing, Router};
use futures::{future, Future, Stream, StreamExt};
use metrics_exporter_prometheus::PrometheusBuilder;
use reqwest::Url;
use std::{fmt::Debug, net::SocketAddr, time::Duration};

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
    tracing::debug!(PF=%setup.pathfinder_url, GW=%setup.gateway_url, "pathfinder-probe starting");

    tokio::spawn(async move {
        stream(
            &setup.gateway_url,
            "GW",
            get_gateway_latest,
            setup.poll_delay,
        )
        .zip(stream(
            &setup.pathfinder_url,
            "PF",
            get_pathfinder_head,
            setup.poll_delay,
        ))
        .for_each(|(gw, pf)| {
            tracing::info!(
                block = gw.block_number,
                time = gw.block_timestamp,
                "gateway"
            );
            tracing::info!(
                block = pf.block_number,
                time = pf.block_timestamp,
                "pathfinder"
            );

            let blocks_missing = gw.block_number - pf.block_number;
            metrics::gauge!("blocks_missing", blocks_missing as f64);

            let blocks_delay = gw.block_timestamp - pf.block_timestamp;
            metrics::gauge!("blocks_delay", blocks_delay as f64);

            future::ready(())
        })
        .await
    });

    tracing::info!(server=?setup.listen_at, "pathfinder-probe running");

    let app = Router::new().route("/metrics", routing::get(|| async move { handle.render() }));

    axum::Server::bind(&setup.listen_at)
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

#[derive(Clone, Debug, Default)]
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
        .context("Failed to parse arguments: <listen-at> <gateway-url> <pathfinder-url> <poll-delay-seconds>")?
}

fn stream<'a, T, R>(
    url: &'a Url,
    tag: &'a str,
    f: fn(&'a Url) -> R,
    delay: Duration,
) -> impl Stream<Item = T> + 'a
where
    R: Future<Output = anyhow::Result<T>> + 'a,
    T: Clone + Debug + Default + 'a,
{
    futures::stream::unfold(T::default(), move |old| async move {
        let new = match f(url).await {
            Ok(new) => new,
            Err(e) => {
                tracing::error!(tag, "error: {e}");
                old
            }
        };
        tracing::debug!(%tag, ?new, "stream");
        tokio::time::sleep(delay).await;
        Some((new.clone(), new))
    })
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
        .context("Failed to fetch block number")?;

    let block_timestamp = json["timestamp"]
        .as_i64()
        .context("Failed to fetch block timestamp")?;

    Ok(Head {
        block_number,
        block_timestamp,
    })
}

// curl -H 'Content-type: application/json' -d '{"jsonrpc":"2.0","method":"starknet_getBlockWithTxHashes","params":["latest"],"id":1}' http://127.0.0.1:9000/rpc/v0.5
async fn get_pathfinder_head(pathfinder_url: &Url) -> anyhow::Result<Head> {
    let json: serde_json::Value = reqwest::ClientBuilder::new().build()?
        .post(pathfinder_url.to_owned())
        .header("Content-type", "application/json")
        .json(&serde_json::json!({"jsonrpc":"2.0","method":"starknet_getBlockWithTxHashes","params":["latest"],"id":1}))
        .timeout(REQUEST_TIMEOUT)
        .send()
        .await?
        .json()
        .await?;

    let block_number = json["result"]
        .as_object()
        .context("Response 'result' missing")?["block_number"]
        .as_i64()
        .context("Failed to fetch block number")?;

    let block_timestamp = json["result"]
        .as_object()
        .context("Response 'result' missing")?["timestamp"]
        .as_i64()
        .context("Failed to fetch block timestamp")?;

    Ok(Head {
        block_number,
        block_timestamp,
    })
}
