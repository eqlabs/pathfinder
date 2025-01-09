#![deny(rust_2018_idioms)]

use std::path::Path;
use std::time::Duration;

use clap::Parser;
use futures::StreamExt;
use libp2p::core::upgrade;
use libp2p::identity::Keypair;
use libp2p::swarm::{Config, SwarmEvent};
use libp2p::{dns, identify, noise, Multiaddr, Swarm, Transport};
use pathfinder_common::ChainId;
use serde::Deserialize;
use zeroize::Zeroizing;

mod behaviour;

#[derive(Parser, Debug)]
struct Args {
    #[clap(long, short, value_parser, env = "IDENTITY_CONFIG_FILE")]
    identity_config_file: Option<std::path::PathBuf>,
    #[clap(long, short, value_parser, env = "LISTEN_ON")]
    listen_on: Multiaddr,
    #[clap(long, short, value_parser, env = "BOOTSTRAP_INTERVAL")]
    bootstrap_interval_seconds: u64,
    #[clap(long, short, value_parser, env = "PRETTY_LOG", default_value = "false")]
    pretty_log: bool,
    #[clap(long, short, value_parser, env = "NETWORK")]
    network: Network,
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

#[derive(clap::ValueEnum, Clone, serde::Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
enum Network {
    Mainnet,
    SepoliaTestnet,
    SepoliaIntegration,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    let args = Args::parse();

    setup_tracing(args.pretty_log);

    let keypair = match &args.identity_config_file {
        Some(path) => {
            let config = Zeroizing::new(IdentityConfig::from_file(path.as_path())?);
            let private_key = Zeroizing::new(base64::decode(config.private_key.as_bytes())?);
            Keypair::from_protobuf_encoding(&private_key)?
        }
        None => {
            tracing::info!("No private key configured, generating a new one");
            Keypair::generate_ed25519()
        }
    };

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "Starting up");

    let transport = libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::new());
    let transport = dns::tokio::Transport::system(transport).unwrap();
    let noise_config =
        noise::Config::new(&keypair).expect("Signing libp2p-noise static DH keypair failed.");
    let transport = transport
        .upgrade(upgrade::Version::V1)
        .authenticate(noise_config)
        .multiplex(libp2p::yamux::Config::default())
        .boxed();

    let chain_id = match args.network {
        Network::Mainnet => ChainId::MAINNET,
        Network::SepoliaTestnet => ChainId::SEPOLIA_TESTNET,
        Network::SepoliaIntegration => ChainId::SEPOLIA_INTEGRATION,
    };
    let mut swarm = Swarm::new(
        transport,
        behaviour::BootstrapBehaviour::new(keypair.public(), chain_id),
        keypair.public().to_peer_id(),
        Config::with_tokio_executor(),
    );

    swarm.listen_on(args.listen_on)?;

    let mut bootstrap_interval =
        tokio::time::interval(Duration::from_secs(args.bootstrap_interval_seconds));

    let mut network_status_interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        let bootstrap_interval_tick = bootstrap_interval.tick();
        tokio::pin!(bootstrap_interval_tick);

        let network_status_interval_tick = network_status_interval.tick();
        tokio::pin!(network_status_interval_tick);

        tokio::select! {
            _ = network_status_interval_tick => {
                let network_info = swarm.network_info();
                let num_peers = network_info.num_peers();
                let connection_counters = network_info.connection_counters();
                let num_established_connections = connection_counters.num_established();
                let num_pending_connections = connection_counters.num_pending();
                tracing::info!(%num_peers, %num_established_connections, %num_pending_connections, "Network status")
            }
            _ = bootstrap_interval_tick => {
                tracing::debug!("Doing periodical bootstrap");
                _ = swarm.behaviour_mut().kademlia.bootstrap();
            }
            Some(event) = swarm.next() => {
                match event {
                    SwarmEvent::Behaviour(behaviour::BootstrapEvent::Identify(e)) => {
                        if let identify::Event::Received {
                            peer_id,
                            info:
                                identify::Info {
                                    listen_addrs,
                                    protocols,
                                    observed_addr,
                                    ..
                                },
                                ..
                        } = *e
                        {
                            // Important change in libp2p-v0.52 compared to v0.51:
                            //
                            // https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.52.0
                            //
                            // As a consequence, the observed address reported by identify is no longer
                            // considered an external address but just an address candidate.
                            //
                            // https://github.com/libp2p/rust-libp2p/blob/master/protocols/identify/CHANGELOG.md#0430
                            //
                            // Observed addresses (aka. external address candidates) of the local node, reported by a remote node via libp2p-identify,
                            // are no longer automatically considered confirmed external addresses, in other words they are no longer trusted by default.
                            // Instead users need to confirm the reported observed address either manually, or by using libp2p-autonat.
                            // In trusted environments users can simply extract observed addresses from a
                            // libp2p-identify::Event::Received { info: libp2p_identify::Info { observed_addr }} and confirm them via Swarm::add_external_address.

                            swarm.add_external_address(observed_addr);

                            let my_kad_names = swarm.behaviour().kademlia.protocol_names();

                            if protocols
                                .iter()
                                .any(|p| my_kad_names.contains(p))
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

fn setup_tracing(pretty_log: bool) {
    let builder = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(pretty_log);
    if pretty_log {
        builder.pretty().init();
    } else {
        builder.compact().init();
    }
}
