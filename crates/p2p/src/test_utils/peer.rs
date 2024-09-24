use std::collections::HashMap;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::identity::Keypair;
use libp2p::{Multiaddr, PeerId};
use pathfinder_common::ChainId;
use tokio::task::JoinHandle;

use crate::peers::Peer;
use crate::{Builder, Config, Event, RateLimit, TestEvent};

#[allow(dead_code)]
#[derive(Debug)]
pub struct TestPeer {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub client: crate::Client,
    pub event_receiver: crate::EventReceiver,
    pub main_loop_jh: JoinHandle<()>,
}

#[derive(Default)]
pub struct TestPeerBuilder {
    p2p_builder: Option<Builder>,
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
            bootstrap_period: Duration::from_millis(500),
            eviction_timeout: Duration::from_secs(15 * 60),
            inbound_connections_rate_limit: RateLimit {
                max: 1000,
                interval: Duration::from_secs(1),
            },
            kad_name: Default::default(),
            stream_timeout: Duration::from_secs(10),
            max_concurrent_streams: 100,
        }
    }
}

impl TestPeerBuilder {
    pub fn p2p_builder(mut self, p2p_builder: Builder) -> Self {
        self.p2p_builder = Some(p2p_builder);
        self
    }

    pub fn build(self, keypair: Keypair, cfg: Config) -> TestPeer {
        let Self { p2p_builder } = self;

        let peer_id = keypair.public().to_peer_id();

        let (client, mut event_receiver, main_loop) = p2p_builder
            .unwrap_or_else(|| crate::Builder::new(keypair.clone(), cfg, ChainId::SEPOLIA_TESTNET))
            .build();

        // Ensure that the channel keeps being polled to move the main loop forward.
        // Store the polled events into a buffered channel instead.
        let (buf_sender, buf_receiver) = tokio::sync::mpsc::channel(1024);
        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                buf_sender.send(event).await.unwrap();
            }
        });

        let main_loop_jh = tokio::spawn(main_loop.run());
        TestPeer {
            keypair,
            peer_id,
            client,
            event_receiver: buf_receiver,
            main_loop_jh,
        }
    }
}

impl TestPeer {
    pub fn builder() -> TestPeerBuilder {
        Default::default()
    }

    /// Create a new peer with a random keypair
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self::builder().build(Keypair::generate_ed25519(), cfg)
    }

    #[must_use]
    pub fn with_keypair(keypair: Keypair, cfg: Config) -> Self {
        Self::builder().build(keypair, cfg)
    }

    /// Start listening on a specified address
    pub async fn start_listening_on(&mut self, addr: Multiaddr) -> Result<Multiaddr> {
        self.client
            .start_listening(addr)
            .await
            .context("Start listening failed")?;

        let event = tokio::time::timeout(Duration::from_secs(1), self.event_receiver.recv())
            .await
            .context("Timedout while waiting for new listen address")?
            .context("Event channel closed")?;

        let addr = match event {
            Event::Test(TestEvent::NewListenAddress(addr)) => addr,
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
    /// Create a new peer with a random keypair and default test config
    fn default() -> Self {
        Self::builder().build(Keypair::generate_ed25519(), Config::for_test())
    }
}
