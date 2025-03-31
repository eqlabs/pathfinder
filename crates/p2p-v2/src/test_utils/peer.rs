use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::identity::Keypair;
use libp2p::swarm::{dummy, NetworkBehaviour};
use libp2p::{Multiaddr, PeerId};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::core::{Client, Config, TestEvent};
use crate::peers::Peer;
use crate::ApplicationBehaviour;

#[allow(dead_code)]
#[derive(Debug)]
pub struct TestPeer<B>
where
    B: ApplicationBehaviour,
    <B as ApplicationBehaviour>::Command: Debug,
{
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub client: Client<<B as ApplicationBehaviour>::Command>,
    pub app_event_receiver: mpsc::Receiver<<B as ApplicationBehaviour>::Event>,
    pub test_event_receiver: mpsc::Receiver<TestEvent>,
    pub main_loop_jh: JoinHandle<()>,
}

pub struct AppBehaviourUnset;
pub struct AppBehaviourSet;

pub struct TestPeerBuilder<B, Phase = AppBehaviourUnset> {
    pub keypair: Keypair,
    enable_kademlia: bool,
    app_behaviour: Option<B>,
    _phase: PhantomData<Phase>,
}

impl<B> TestPeerBuilder<B, AppBehaviourUnset> {
    pub fn new() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
            enable_kademlia: true,
            app_behaviour: None,
            _phase: PhantomData,
        }
    }

    pub fn app_behaviour(self, app_behaviour: B) -> TestPeerBuilder<B, AppBehaviourSet> {
        TestPeerBuilder {
            keypair: self.keypair,
            enable_kademlia: self.enable_kademlia,
            app_behaviour: Some(app_behaviour),
            _phase: PhantomData,
        }
    }
}

impl<B, AnyPhase> TestPeerBuilder<B, AnyPhase> {
    pub fn keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
        self
    }

    pub fn disable_kademlia(mut self) -> Self {
        self.enable_kademlia = false;
        self
    }
}

impl<B> TestPeerBuilder<B, AppBehaviourSet>
where
    B: ApplicationBehaviour + Send,
    <B as NetworkBehaviour>::ToSwarm: Debug,
    <B as ApplicationBehaviour>::Command: Debug + Send,
    <B as ApplicationBehaviour>::Event: Send,
    <B as ApplicationBehaviour>::State: Default + Send,
{
    pub fn build(self, cfg: Config) -> TestPeer<B> {
        let Self {
            keypair,
            enable_kademlia,
            app_behaviour,
            ..
        } = self;

        let peer_id = keypair.public().to_peer_id();

        let p2p_builder = crate::Builder::new(keypair.clone(), cfg, ChainId::SEPOLIA_TESTNET);

        let p2p_builder = if enable_kademlia {
            p2p_builder
        } else {
            p2p_builder.disable_kademlia_for_test()
        };

        let (client, mut event_receiver, mut main_loop) = p2p_builder
            .app_behaviour(app_behaviour.expect("App behaviour to be set in this phase"))
            .build();

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

impl TestPeerBuilder<dummy::Behaviour, AppBehaviourUnset> {
    pub fn build(self, cfg: Config) -> TestPeer<dummy::Behaviour> {
        self.app_behaviour(dummy::Behaviour).build(cfg)
    }
}

impl TestPeer<dummy::Behaviour> {
    /// Create a new peer with a random keypair
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self::builder().build(cfg)
    }

    #[must_use]
    pub fn with_keypair(keypair: Keypair, cfg: Config) -> Self {
        Self::builder().keypair(keypair).build(cfg)
    }
}

impl<B> TestPeer<B>
where
    B: ApplicationBehaviour + Send,
    <B as NetworkBehaviour>::ToSwarm: Debug,
    <B as ApplicationBehaviour>::Command: Debug + Send,
    <B as ApplicationBehaviour>::Event: Send,
    <B as ApplicationBehaviour>::State: Default + Send,
{
    pub fn builder() -> TestPeerBuilder<B> {
        TestPeerBuilder::new()
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

impl Default for TestPeer<dummy::Behaviour> {
    fn default() -> Self {
        Self::new(Config::for_test())
    }
}
