#![deny(rust_2018_idioms)]

use std::sync::Arc;
use std::{path::Path, time::Duration};

use clap::Parser;
use libp2p::Multiaddr;
use libp2p::{identity::Keypair, PeerId};
use p2p::Peers;
use p2p_proto as proto;
use proto::sync::{BlockBodies, StateDiffs};
use serde_derive::Deserialize;
use stark_hash::Felt;
use tokio::sync::RwLock;
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

    let peers: Arc<RwLock<Peers>> = Arc::new(RwLock::new(Default::default()));
    let (p2p_client, mut p2p_events, p2p_main_loop) =
        p2p::new(keypair, peers.clone(), Default::default());

    let _p2p_task = tokio::task::spawn(p2p_main_loop.run());

    p2p_client.start_listening(args.listen_on).await?;

    for bootstrap_address in args.bootstrap_addresses {
        let peer_id = bootstrap_address
            .iter()
            .find_map(|p| match p {
                libp2p::multiaddr::Protocol::P2p(h) => PeerId::from_multihash(h).ok(),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("Boostrap addresses must inlcude peer ID"))?;
        p2p_client.dial(peer_id, bootstrap_address.clone()).await?;
        p2p_client
            .start_listening(bootstrap_address.with(libp2p::multiaddr::Protocol::P2pCircuit))
            .await?;
    }

    let capabilities = ["core/block-propagate/1", "core/blocks-sync/1"];
    for capability in capabilities {
        p2p_client.provide_capability(capability).await?
    }

    // SN_GOERLI chain ID
    const GOERLI_CHAIN_ID: u128 = 0x534e5f474f45524c49u128;
    let block_propagation_topic = format!("blocks/{GOERLI_CHAIN_ID:#x}");
    p2p_client.subscribe_topic(&block_propagation_topic).await?;

    if args.emit_events {
        let client = p2p_client.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(10));
            loop {
                ticker.tick().await;

                let message = proto::propagation::Message::NewBlockHeader(
                    proto::propagation::NewBlockHeader {
                        header: Default::default(),
                    },
                );
                match client
                    .publish_propagation_message(&block_propagation_topic, message)
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
            p2p::Event::SyncPeerConnected { peer_id }
            | p2p::Event::SyncPeerRequestStatus { peer_id } => {
                use p2p_proto::sync::Status;

                p2p_client
                    .send_sync_status_request(
                        peer_id,
                        Status {
                            chain_id: GOERLI_CHAIN_ID.into(),
                            height: 128,
                            hash: Felt::ZERO,
                        },
                    )
                    .await;
            }
            p2p::Event::InboundSyncRequest {
                request, channel, ..
            } => {
                use p2p_proto::sync::{BlockHeaders, Request, Response, Status};
                let response = match request {
                    Request::GetBlockHeaders(_r) => {
                        Response::BlockHeaders(BlockHeaders { headers: vec![] })
                    }
                    Request::GetBlockBodies(_r) => Response::BlockBodies(BlockBodies {
                        block_bodies: vec![],
                    }),
                    Request::GetStateDiffs(_r) => Response::StateDiffs(StateDiffs {
                        block_state_updates: vec![],
                    }),
                    Request::Status(_) => Response::Status(Status {
                        chain_id: GOERLI_CHAIN_ID.into(),
                        height: 128,
                        hash: Felt::ZERO,
                    }),
                };
                p2p_client.send_sync_response(channel, response).await;
            }
            p2p::Event::BlockPropagation(block_propagation) => {
                tracing::info!(?block_propagation, "Block Propagation");
            }
            p2p::Event::Test(_) => {}
        }
    }

    Ok(())
}

fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .compact()
        .init();
}
