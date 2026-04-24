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

use crate::builder_phase::*;
use crate::core::{Client, Config, TestEvent};
use crate::peers::Peer;
use crate::ApplicationBehaviour;

/// Create a pair of connected peers. The first peer is the server that listens
/// for incoming connections, and the second peer is the client that dials the
/// server. `create_peer_fn` is a function that creates a new peer with the
/// desired applicationbehaviour.
pub async fn create_and_connect_pair<F, B>(create_peer_fn: F) -> (TestPeer<B>, TestPeer<B>)
where
    F: Fn() -> TestPeer<B>,
    B: ApplicationBehaviour + Send,
    <B as NetworkBehaviour>::ToSwarm: Debug,
    <B as ApplicationBehaviour>::Command: Debug + Send,
    <B as ApplicationBehaviour>::Event: Send,
    <B as ApplicationBehaviour>::State: Default + Send,
{
    let mut server = create_peer_fn();
    let client = create_peer_fn();

    let server_addr = server.start_listening().await.unwrap();

    tracing::info!(%server.peer_id, %server_addr, "Server");
    tracing::info!(%client.peer_id, "Client");

    client
        .client
        .dial(server.peer_id, server_addr)
        .await
        .unwrap();

    (server, client)
}

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
    pub app_event_receiver: mpsc::UnboundedReceiver<<B as ApplicationBehaviour>::Event>,
    pub test_event_receiver: mpsc::UnboundedReceiver<TestEvent>,
    pub main_loop_jh: JoinHandle<()>,
}

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

        let (client, app_event_receiver, mut main_loop) = p2p_builder
            .app_behaviour(app_behaviour.expect("App behaviour to be set in this phase"))
            .build();

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
    async fn start_listening_on(&mut self, addr: Multiaddr) -> Result<Multiaddr> {
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

    /// Wait for a specific test event to happen. Extract data from the event
    /// using the provided function `f`.
    pub async fn wait_for_event<Data>(
        &mut self,
        f: impl FnMut(<B as ApplicationBehaviour>::Event) -> Option<Data>,
    ) -> Option<Data>
    where
        Data: Debug + Send + 'static,
    {
        Self::wait_for_event_impl::<<B as ApplicationBehaviour>::Event, Data>(
            &mut self.app_event_receiver,
            f,
        )
        .await
    }

    /// Wait for a specific test event to happen. Extract data from the event
    /// using the provided function `f`.
    pub async fn wait_for_test_event<Data>(
        &mut self,
        f: impl FnMut(TestEvent) -> Option<Data>,
    ) -> Option<Data>
    where
        Data: Debug + Send + 'static,
    {
        Self::wait_for_event_impl::<TestEvent, Data>(&mut self.test_event_receiver, f).await
    }

    async fn wait_for_event_impl<Event, Data>(
        receiver: &mut mpsc::UnboundedReceiver<Event>,
        mut f: impl FnMut(Event) -> Option<Data>,
    ) -> Option<Data>
    where
        Event: Send + 'static,
        Data: Debug + Send + 'static,
    {
        while let Some(event) = receiver.recv().await {
            if let Some(data) = f(event) {
                return Some(data);
            }
        }
        None
    }
}

impl Default for TestPeer<dummy::Behaviour> {
    fn default() -> Self {
        Self::new(Config::for_test())
    }
}
