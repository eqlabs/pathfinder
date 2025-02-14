#![deny(rust_2018_idioms)]

use std::env::args;
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use p2p::RateLimit;
use p2p_proto::common::{BlockNumberOrHash, Direction, Iteration};
use p2p_proto::transaction::TransactionsRequest;
use pathfinder_common::ChainId;

const USAGE: &str = "Usage: stress_test_sync_client <server-multiaddr-with-peer-id> \
                     <max-concurrent-request-streams> <num-requests> <initial-delay-ms>";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let server_addr = args().nth(1).context(USAGE)?;
    let server_addr = Multiaddr::from_str(&server_addr).context(USAGE)?;
    let server_peer_id = server_addr
        .iter()
        .find_map(|x| match x {
            Protocol::P2p(peer_id) => Some(peer_id),
            _ => None,
        })
        .context(USAGE)?;
    let max_concurrent_streams = args()
        .nth(2)
        .unwrap_or("1000".to_string())
        .parse::<usize>()
        .context(USAGE)?;
    let num_requests = args()
        .nth(3)
        .unwrap_or("1000".to_string())
        .parse::<u64>()
        .context(USAGE)?;
    let initial_delay_ms = args()
        .nth(4)
        .unwrap_or("0".to_string())
        .parse::<u64>()
        .context(USAGE)?;
    let initial_delay = Duration::from_millis(initial_delay_ms);

    let keypair = Keypair::generate_ed25519();
    let (client, mut event_rx, main_loop) = p2p::new(
        keypair,
        p2p::Config {
            direct_connection_timeout: Duration::from_secs(60 * 60),
            relay_connection_timeout: Duration::from_secs(1),
            max_inbound_direct_peers: 10,
            max_inbound_relayed_peers: 0,
            max_outbound_peers: 10,
            eviction_timeout: Duration::ZERO,
            ip_whitelist: Default::default(),
            bootstrap_period: None,
            inbound_connections_rate_limit: RateLimit {
                max: 10,
                interval: Duration::from_secs(1),
            },
            kad_name: None,
            stream_timeout: Duration::from_secs(60 * 60),
            max_concurrent_streams,
        },
        ChainId::SEPOLIA_TESTNET,
    );

    let main_loop_handle = tokio::task::spawn(main_loop.run());

    client
        .start_listening("/ip4/0.0.0.0/tcp/0".parse().expect("Valid multiaddr"))
        .await?;

    client.dial(server_peer_id, server_addr.clone()).await?;

    tracing::info!("Waiting to start sending requests...");

    tokio::time::sleep(initial_delay).await;

    let client_fut = futures::stream::iter(0..num_requests).map(|start| {
        let client = client.clone();
        async move {
            tracing::info!(%start, "Requesting transactions for");
            match client
                .send_transactions_sync_request(
                    server_peer_id,
                    TransactionsRequest {
                        iteration: Iteration {
                            start: BlockNumberOrHash::Number(start * 1000),
                            direction: Direction::Forward,
                            // Max allowed by pathfinder (as a server)
                            limit: 1000,
                            step: 1.into(),
                        },
                    },
                )
                .await
            {
                Ok(mut rx) => {
                    let mut txn_counter = 0;
                    while let Some(response) = rx.next().await {
                        match response {
                            Ok(_) => {
                                txn_counter += 1;
                            }
                            Err(error) => {
                                tracing::warn!(%start, %error, "Failed to get response after {txn_counter} responses");
                                return;
                            }
                        }
                    }

                    tracing::info!(%start, "++++ Received {txn_counter} transactions for");
                }
                Err(error) => tracing::warn!(%start, %error, "Failed to get response stream for"),
            }
        }
    }).buffer_unordered(max_concurrent_streams).fold((), |_, _| async {});

    tokio::select! {
        event = event_rx.recv() => {
            tracing::debug!("Received event: {:?}", event);
        }
        _ = main_loop_handle => {
            println!("Main loop finished");
        }
        _ = client_fut => {
            println!("Client finished");
        }
    }

    Ok(())
}
