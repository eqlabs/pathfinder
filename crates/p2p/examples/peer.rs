#![deny(rust_2018_idioms)]

use std::{
    path::Path,
    time::{Duration, SystemTime},
};

use clap::Parser;
use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use p2p::{BlockPropagation, Event};
use p2p_proto::proto::propagation::NewBlockHeader;
use serde_derive::Deserialize;
use stark_hash::StarkHash;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, value_parser, env = "IDENTITY_CONFIG_FILE")]
    identity_config_file: Option<std::path::PathBuf>,
    #[clap(long, value_parser, env = "LISTEN_ON")]
    listen_on: Multiaddr,
    #[clap(long, value_parser, env = "BOOTSTRAP_ADDRESSES")]
    bootstrap_addresses: Vec<Multiaddr>,
    #[clap(long)]
    emit_events: bool,
}

#[derive(Clone, Deserialize)]
struct IdentityConfig {
    pub private_key: String,
}

impl IdentityConfig {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }
}

impl zeroize::Zeroize for IdentityConfig {
    fn zeroize(&mut self) {
        self.private_key.zeroize()
    }
}

pub struct TokioExecutor();

impl libp2p::core::Executor for TokioExecutor {
    fn exec(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'static + Send>>,
    ) {
        tokio::task::spawn(future);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    setup_tracing();

    let args = Args::parse();
    let keypair = match &args.identity_config_file {
        Some(path) => {
            let config = Zeroizing::new(IdentityConfig::from_file(path.as_path())?);
            let private_key = Zeroizing::new(base64::decode(config.private_key.as_bytes())?);
            Keypair::from_protobuf_encoding(&private_key)?
        }
        None => {
            tracing::info!("No private key configured, generating a new one");
            Keypair::Ed25519(libp2p::identity::ed25519::Keypair::generate())
        }
    };

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "Starting up");

    let (mut p2p_client, mut p2p_events, p2p_main_loop) = p2p::new(keypair);

    let _p2p_task = tokio::task::spawn(p2p_main_loop.run());

    p2p_client.start_listening(args.listen_on).await?;

    for bootstrap_address in args.bootstrap_addresses {
        p2p_client.dial(bootstrap_address).await?;
    }

    let capabilities = ["core/block-propagate/1", "core/blocks-sync/1"];
    for capability in capabilities {
        p2p_client.provide_capability(capability).await?
    }

    // SN_GOERLI chain ID
    const GOERLI_CHAIN_ID: u128 = 0x534e5f474f45524c49u128;
    let block_propagation_topic = format!("blocks/{:#x}", GOERLI_CHAIN_ID);
    p2p_client.subscribe_topic(&block_propagation_topic).await?;

    // echo '{"private_key":"CAESQD2O1wg6Zff85HcP2WroCxkSjjWF0j1MZDd+v46yOQFDcparn+5uwE1jnvPTNa8l3GKwfdh9SDMLSPeyN3aHxfk="}' > identity.json
    // RUST_LOG=info cargo run -p p2p_bootstrap -- --identity-config-file ./identity.json --listen-on /ip4/127.0.0.1/tcp/4000
    // RUST_LOG=info cargo run -p p2p --example peer -- --listen-on /ip4/127.0.0.1/tcp/4001 --bootstrap-addresses /ip4/127.0.0.1/tcp/4000/p2p/12D3KooWHXfu9x4rXGTqYwXhdb69iatUxKnRU8PyPWbg3k4qLNwr --emit-events
    // RUST_LOG=info cargo run -p p2p --example peer -- --listen-on /ip4/127.0.0.1/tcp/4002 --bootstrap-addresses /ip4/127.0.0.1/tcp/4000/p2p/12D3KooWHXfu9x4rXGTqYwXhdb69iatUxKnRU8PyPWbg3k4qLNwr
    // RUST_LOG=info cargo run -p p2p --example peer -- --listen-on /ip4/127.0.0.1/tcp/4003 --bootstrap-addresses /ip4/127.0.0.1/tcp/4000/p2p/12D3KooWHXfu9x4rXGTqYwXhdb69iatUxKnRU8PyPWbg3k4qLNwr

    if args.emit_events {
        let mut client = p2p_client.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;

                let request_id = SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                let new_block_header = NewBlockHeader {
                    request_id,
                    ..Default::default()
                };
                let block_propagation = BlockPropagation::NewBlockHeader(new_block_header);
                match client
                    .publish_event(
                        &block_propagation_topic,
                        Event::BlockPropagation(block_propagation),
                    )
                    .await
                {
                    Ok(_) => tracing::info!("event published"),
                    Err(e) => tracing::error!("event publising failed: {}", e),
                }
            }
        });
    }

    while let Some(event) = p2p_events.recv().await {
        match event {
            p2p::Event::SyncPeerConnected { peer_id } => {
                use p2p_proto::sync::{GetBlockHeaders, Request};

                let mut p2p_client = p2p_client.clone();

                tokio::spawn(async move {
                    let response = p2p_client
                        .send_sync_request(
                            peer_id,
                            Request::GetBlockHeaders(GetBlockHeaders {
                                start_block: StarkHash::ZERO,
                                count: 1,
                                size_limit: 1_000_000,
                                direction: p2p_proto::sync::Direction::Forward,
                            }),
                        )
                        .await;
                    tracing::debug!(?response, "Received response");
                });
            }
            p2p::Event::InboundSyncRequest { request, channel } => {
                tracing::debug!(?request, "Received request");
                use p2p_proto::sync::{BlockHeaders, Response};
                let response = Response::BlockHeaders(BlockHeaders { headers: vec![] });
                p2p_client.send_sync_response(channel, response).await;
            }
            p2p::Event::BlockPropagation(block_propagation) => {
                tracing::info!(?block_propagation, "Block Propagation");
            }
        }
    }

    Ok(())
}

fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();
}
