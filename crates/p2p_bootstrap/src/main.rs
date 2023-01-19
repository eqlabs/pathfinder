#![deny(rust_2018_idioms)]

use std::path::Path;
use std::time::Duration;

use clap::Parser;
use futures::StreamExt;
use libp2p::core::upgrade;
use libp2p::identify::{Event as IdentifyEvent, Info as IdentifyInfo};
use libp2p::identity::Keypair;
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Transport;
use libp2p::{dns, noise, Multiaddr};
use serde_derive::Deserialize;
use zeroize::Zeroizing;

mod behaviour;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, value_parser, env = "IDENTITY_CONFIG_FILE")]
    identity_config_file: Option<std::path::PathBuf>,
    #[clap(long, value_parser, env = "LISTEN_ON")]
    listen_on: Multiaddr,
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

impl libp2p::swarm::Executor for TokioExecutor {
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

    let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new());
    let transport = dns::TokioDnsConfig::system(transport).unwrap();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .expect("Signing libp2p-noise static DH keypair failed.");
    let transport = transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(libp2p::yamux::YamuxConfig::default())
        .boxed();

    let mut swarm = SwarmBuilder::with_executor(
        transport,
        behaviour::BootstrapBehaviour::new(keypair.public()),
        keypair.public().to_peer_id(),
        TokioExecutor(),
    )
    .build();

    swarm.listen_on(args.listen_on)?;

    const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);
    let mut bootstrap_interval = tokio::time::interval(BOOTSTRAP_INTERVAL);

    loop {
        let bootstrap_interval_tick = bootstrap_interval.tick();
        tokio::pin!(bootstrap_interval_tick);

        tokio::select! {
            _ = bootstrap_interval_tick => {
                tracing::debug!("Doing periodical bootstrap");
                _ = swarm.behaviour_mut().kademlia.bootstrap();

                let network_info = swarm.network_info();
                let num_peers = network_info.num_peers();
                let connection_counters = network_info.connection_counters();
                let num_connections = connection_counters.num_connections();
                tracing::info!(%num_peers, %num_connections, "Peer-to-peer status")
            }
            Some(event) = swarm.next() => {
                match event {
                    SwarmEvent::Behaviour(behaviour::BootstrapEvent::Identify(e)) => {
                        if let IdentifyEvent::Received {
                            peer_id,
                            info:
                                IdentifyInfo {
                                    listen_addrs,
                                    protocols,
                                    ..
                                },
                        } = *e
                        {
                            if protocols
                                .iter()
                                .any(|p| p.as_bytes() == behaviour::KADEMLIA_PROTOCOL_NAME)
                            {
                                for addr in listen_addrs {
                                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                }
                                tracing::debug!(%peer_id, "Added peer to DHT");
                            }
                        }
                    }
                    e => {
                        tracing::debug!(?e, "Swarm Event");
                    }
                }
            }
        }
    }
}

fn setup_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .compact()
        .init();
}
