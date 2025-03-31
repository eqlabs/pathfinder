use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::identity::Keypair;
use libp2p::swarm::{dummy, NetworkBehaviour};
use libp2p::{Multiaddr, PeerId};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::{Config, RateLimit};
use crate::core::client::Client;
use crate::core::TestEvent;
use crate::peers::Peer;
use crate::{Builder, P2PApplicationBehaviour};

#[allow(dead_code)]
#[derive(Debug)]
pub struct TestPeer {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub client: Client<<dummy::Behaviour as P2PApplicationBehaviour>::Command>,
    pub app_event_receiver: mpsc::Receiver<<dummy::Behaviour as P2PApplicationBehaviour>::Event>,
    pub test_event_receiver: mpsc::Receiver<TestEvent>,
    pub main_loop_jh: JoinHandle<()>,
}

pub struct TestPeerBuilder {
    pub keypair: Keypair,
    p2p_builder: Option<Builder>,
    enable_kademlia: bool,
}

impl Config {
    pub fn for_test() -> Self {
        Self {
            direct_connection_timeout: Duration::from_secs(0),
            relay_connection_timeout: Duration::from_secs(0),
            max_inbound_direct_peers: 10,
            max_inbound_relayed_peers: 10,
            max_outbound_peers: 10,
            ip_whitelist: vec!["::1/0".parse().unwrap(), "0.0.0.0/0".parse().unwrap()],
            bootstrap_period: None,
            eviction_timeout: Duration::from_secs(15 * 60),
            inbound_connections_rate_limit: RateLimit {
                max: 1000,
                interval: Duration::from_secs(1),
            },
            kad_name: Default::default(),
        }
    }
}

impl TestPeerBuilder {
    pub fn new() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
            p2p_builder: None,
            enable_kademlia: true,
        }
    }

    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
        self
    }

    pub fn p2p_builder(mut self, p2p_builder: Builder) -> Self {
        self.p2p_builder = Some(p2p_builder);
        self
    }

    pub fn disable_kademlia(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }

    pub fn build(self, cfg: Config) -> TestPeer {
        let Self {
            keypair,
            p2p_builder,
            enable_kademlia,
        } = self;

        let peer_id = keypair.public().to_peer_id();

        let p2p_builder = p2p_builder
            .unwrap_or_else(|| crate::Builder::new(keypair.clone(), cfg, ChainId::SEPOLIA_TESTNET));

        let p2p_builder = if enable_kademlia {
            p2p_builder
        } else {
            p2p_builder.disable_kademlia_for_test()
        };

        let (client, mut event_receiver, mut main_loop) = p2p_builder.build();

        // Ensure that the channel keeps being polled to move the main loop forward.
        // Store the polled events into a buffered channel instead.
        let (buf_sender, app_event_receiver) = tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                buf_sender.send(event).await.unwrap();
            }
        });

        let test_event_receiver = main_loop.take_test_event_receiver();

        let main_loop_jh = tokio::spawn(main_loop.run());
        TestPeer {
            keypair,
            peer_id,
            client,
            app_event_receiver,
            test_event_receiver,
            main_loop_jh,
        }
    }
}

impl TestPeer {
    pub fn builder() -> TestPeerBuilder {
        TestPeerBuilder::new()
    }

    /// Create a new peer with a random keypair
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self::builder().build(cfg)
    }

    #[must_use]
    pub fn with_keypair(keypair: Keypair, cfg: Config) -> Self {
        Self::builder().keypair(keypair).build(cfg)
    }

    /// Start listening on a specified address
    pub async fn start_listening_on(&mut self, addr: Multiaddr) -> Result<Multiaddr> {
        self.client
            .start_listening(addr)
            .await
            .context("Start listening failed")?;

        let event = tokio::time::timeout(Duration::from_secs(1), self.test_event_receiver.recv())
            .await
            .context("Timedout while waiting for new listen address")?
            .context("Event channel closed")?;

        let addr = match event {
            TestEvent::NewListenAddress(addr) => addr,
            _ => anyhow::bail!("Unexpected event: {event:?}"),
        };
        Ok(addr)
    }

    /// Start listening on localhost with port automatically assigned
    pub async fn start_listening(&mut self) -> Result<Multiaddr> {
        self.start_listening_on(Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap())
            .await
    }

    /// Get peer IDs of the connected peers
    pub async fn connected(&self) -> HashMap<PeerId, Peer> {
        self.client.for_test().get_connected_peers().await
    }
}

impl Default for TestPeer {
    fn default() -> Self {
        Self::new(Config::for_test())
    }
}
