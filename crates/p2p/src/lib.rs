#![deny(rust_2018_idioms)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use delay_map::HashSetDelay;
use futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic};
use libp2p::identity::Keypair;
use libp2p::kad::record::Key;
use libp2p::kad::{BootstrapError, BootstrapOk, KademliaEvent, QueryId, QueryResult};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, RequestId, ResponseChannel};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;
use libp2p::{identify, PeerId};
use pathfinder_common::{BlockHash, BlockNumber, ClassHash};
use tokio::sync::{mpsc, oneshot, RwLock};

mod behaviour;
mod executor;
mod peers;
mod sync;
#[cfg(test)]
mod test_utils;
#[cfg(test)]
mod tests;
mod transport;

pub use peers::Peers;

pub use libp2p;

pub fn new(
    keypair: Keypair,
    peers: Arc<RwLock<peers::Peers>>,
    periodic_cfg: PeriodicTaskConfig,
) -> (Client, EventReceiver, MainLoop) {
    let my_peer_id = keypair.public().to_peer_id();

    let (behaviour, relay_transport) = behaviour::Behaviour::new(&keypair);

    let swarm = SwarmBuilder::with_executor(
        transport::create(&keypair, relay_transport),
        behaviour,
        my_peer_id,
        executor::TokioExecutor(),
    )
    .build();

    let (command_sender, command_receiver) = mpsc::channel(1);
    let (event_sender, event_receiver) = mpsc::channel(1);

    (
        Client {
            sender: command_sender,
            my_peer_id,
        },
        event_receiver,
        MainLoop::new(swarm, command_receiver, event_sender, peers, periodic_cfg),
    )
}

#[derive(Copy, Clone, Debug)]
pub struct PeriodicTaskConfig {
    pub bootstrap: BootstrapConfig,
    pub status_period: Duration,
}

#[derive(Copy, Clone, Debug)]
pub struct BootstrapConfig {
    pub start_offset: Duration,
    pub period: Duration,
}

impl Default for PeriodicTaskConfig {
    fn default() -> Self {
        Self {
            bootstrap: BootstrapConfig {
                start_offset: Duration::from_secs(5),
                period: Duration::from_secs(10 * 60),
            },
            status_period: Duration::from_secs(30),
        }
    }
}

/// _High level_ client for p2p interaction.
/// Frees the caller from managing peers manually.
#[derive(Clone, Debug)]
pub struct SyncClient {
    client: Client,
    block_propagation_topic: String,
    peers_with_sync_capability: Arc<RwLock<HashSet<PeerId>>>,
    last_update: Arc<RwLock<std::time::Instant>>,
    // FIXME
    _peers: Arc<RwLock<peers::Peers>>,
}

pub type HeadTx = tokio::sync::watch::Sender<Option<(BlockNumber, BlockHash)>>;
pub type HeadRx = tokio::sync::watch::Receiver<Option<(BlockNumber, BlockHash)>>;

// FIXME make sure the api looks reasonable from the perspective of
// the __user__, which is the sync driving algo/entity
impl SyncClient {
    pub fn new(
        client: Client,
        block_propagation_topic: String,
        peers: Arc<RwLock<peers::Peers>>,
    ) -> Self {
        Self {
            client,
            block_propagation_topic,
            peers_with_sync_capability: Default::default(),
            last_update: Arc::new(RwLock::new(
                std::time::Instant::now()
                    .checked_sub(Duration::from_secs(55))
                    .unwrap(),
            )),
            _peers: peers,
        }
    }

    // Propagate new L2 head header
    pub async fn propagate_new_header(
        &self,
        header: p2p_proto::common::BlockHeader,
    ) -> anyhow::Result<()> {
        tracing::debug!(block_number=%header.number, topic=%self.block_propagation_topic,
            "Propagating header"
        );

        self.client
            .publish_propagation_message(
                &self.block_propagation_topic,
                p2p_proto::propagation::Message::NewBlockHeader(
                    p2p_proto::propagation::NewBlockHeader { header },
                ),
            )
            .await
    }

    async fn get_update_peers_with_sync_capability(&self) -> Vec<PeerId> {
        use rand::seq::SliceRandom;

        if self.last_update.read().await.clone().elapsed() > Duration::from_secs(60) {
            let mut peers = self
                .client
                .get_capability_providers("core/blocks-sync/1")
                .await
                .unwrap_or_default();

            let _i_should_have_the_capability_too = peers.remove(&self.client.my_peer_id);
            debug_assert!(_i_should_have_the_capability_too);

            let mut peers_with_sync_capability = self.peers_with_sync_capability.write().await;
            *peers_with_sync_capability = peers;

            let mut last_update = self.last_update.write().await;
            *last_update = std::time::Instant::now();
        }

        let peers_with_sync_capability = self.peers_with_sync_capability.read().await;
        let mut peers = peers_with_sync_capability
            .iter()
            .map(Clone::clone)
            .collect::<Vec<_>>();
        peers.shuffle(&mut rand::thread_rng());
        peers
    }

    pub async fn block_headers(
        &self,
        // start_block_hash: BlockHash, // FIXME, hash to avoid DB lookup
        start_block: BlockNumber, // TODO number or hash
        num_blocks: usize,        // FIXME, use range?
    ) -> Option<Vec<p2p_proto::common::BlockHeader>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self
                .client
                .send_sync_request(
                    peer,
                    p2p_proto::sync::Request::GetBlockHeaders(p2p_proto::sync::GetBlockHeaders {
                        start_block: start_block.get(),
                        count,
                        size_limit: u64::MAX, // FIXME
                        direction: p2p_proto::sync::Direction::Forward,
                    }),
                )
                .await;

            match response {
                Ok(p2p_proto::sync::Response::BlockHeaders(x)) => {
                    if x.headers.is_empty() {
                        tracing::debug!(%peer, "Got empty block headers response");
                        continue;
                    } else {
                        return Some(x.headers);
                    }
                }
                Ok(_) => {
                    tracing::debug!(%peer, "Got unexpected response to GetBlockHeaders");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetBlockHeaders failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block, %num_blocks, "No peers with block headers found for");

        None
    }

    pub async fn block_bodies(
        &self,
        start_block_hash: BlockHash, // FIXME, hash to avoid DB lookup
        num_blocks: usize,           // FIXME, use range?
    ) -> Option<Vec<p2p_proto::common::BlockBody>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self
                .client
                .send_sync_request(
                    peer,
                    p2p_proto::sync::Request::GetBlockBodies(p2p_proto::sync::GetBlockBodies {
                        start_block: start_block_hash.0,
                        count,
                        size_limit: u64::MAX, // FIXME
                        direction: p2p_proto::sync::Direction::Forward,
                    }),
                )
                .await;

            match response {
                Ok(p2p_proto::sync::Response::BlockBodies(x)) => {
                    if x.block_bodies.is_empty() {
                        tracing::debug!(%peer, "Got empty block bodies response");
                        continue;
                    } else {
                        return Some(x.block_bodies);
                    }
                }
                Ok(_) => {
                    tracing::debug!(%peer, "Got unexpected response to GetBlockBodies");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetBlockBodies failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block_hash, %num_blocks, "No peers with block bodies found for");

        None
    }

    pub async fn state_updates(
        &self,
        start_block_hash: BlockHash, // FIXME, hash to avoid DB lookup
        num_blocks: usize,           // FIXME, use range?
    ) -> Option<Vec<p2p_proto::sync::BlockStateUpdateWithHash>> {
        if num_blocks == 0 {
            return Some(Vec::new());
        }

        let count: u64 = num_blocks.try_into().ok()?;

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self
                .client
                .send_sync_request(
                    peer,
                    p2p_proto::sync::Request::GetStateDiffs(p2p_proto::sync::GetStateDiffs {
                        start_block: start_block_hash.0,
                        count,
                        size_limit: u64::MAX, // FIXME
                        direction: p2p_proto::sync::Direction::Forward,
                    }),
                )
                .await;
            match response {
                Ok(p2p_proto::sync::Response::StateDiffs(x)) => {
                    if x.block_state_updates.is_empty() {
                        tracing::debug!(%peer, "Got empty state updates response");
                        continue;
                    } else {
                        return Some(x.block_state_updates);
                    }
                }
                Ok(_) => {
                    tracing::debug!(%peer, "Got unexpected response to GetStateDiffs");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetStateDiffs failed");
                    continue;
                }
            }
        }

        tracing::debug!(%start_block_hash, %num_blocks, "No peers with state updates found for");

        None
    }

    pub async fn contract_classes(
        &self,
        class_hashes: Vec<ClassHash>,
    ) -> Option<p2p_proto::sync::Classes> {
        if class_hashes.is_empty() {
            return Some(p2p_proto::sync::Classes {
                classes: Vec::new(),
            });
        }

        let class_hashes = class_hashes.into_iter().map(|x| x.0).collect::<Vec<_>>();

        for peer in self.get_update_peers_with_sync_capability().await {
            let response = self
                .client
                .send_sync_request(
                    peer,
                    p2p_proto::sync::Request::GetClasses(p2p_proto::sync::GetClasses {
                        class_hashes: class_hashes.clone(),
                        size_limit: u64::MAX, // FIXME
                    }),
                )
                .await;
            match response {
                Ok(p2p_proto::sync::Response::Classes(x)) => {
                    if x.classes.is_empty() {
                        tracing::debug!(%peer, "Got empty classes response");
                        continue;
                    } else {
                        return Some(x);
                    }
                }
                Ok(_) => {
                    tracing::debug!(%peer, "Got unexpected response to GetClasses");
                    continue;
                }
                Err(error) => {
                    tracing::debug!(%peer, %error, "GetStateDiffs failed");
                    continue;
                }
            }
        }

        tracing::debug!(?class_hashes, "No peers with classes found for");

        None
    }
}

/// _Low level_ client for p2p interaction.
/// For syncing use [`SyncClient`] instead.
#[derive(Clone, Debug)]
pub struct Client {
    sender: mpsc::Sender<Command>,
    my_peer_id: PeerId,
}

impl Client {
    pub async fn start_listening(&self, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StarListening { addr, sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn dial(&self, peer_id: PeerId, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Dial {
                peer_id,
                addr,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn provide_capability(&self, capability: &str) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::ProvideCapability {
                capability: capability.to_owned(),
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn get_capability_providers(
        &self,
        capability: &str,
    ) -> anyhow::Result<HashSet<PeerId>> {
        let (sender, mut receiver) = mpsc::channel(1);
        self.sender
            .send(Command::GetCapabilityProviders {
                capability: capability.to_owned(),
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");

        let mut providers = HashSet::new();

        while let Some(partial_result) = receiver.recv().await {
            let more_providers =
                partial_result.with_context(|| format!("Getting providers for {capability}"))?;
            providers.extend(more_providers.into_iter());
        }

        Ok(providers)
    }

    pub async fn subscribe_topic(&self, topic: &str) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::SubscribeTopic { topic, sender })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn send_sync_request(
        &self,
        peer_id: PeerId,
        request: p2p_proto::sync::Request,
    ) -> anyhow::Result<p2p_proto::sync::Response> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::SendSyncRequest {
                peer_id,
                request,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn send_sync_response(
        &self,
        channel: ResponseChannel<p2p_proto::sync::Response>,
        response: p2p_proto::sync::Response,
    ) {
        self.sender
            .send(Command::SendSyncResponse { channel, response })
            .await
            .expect("Command receiver not to be dropped");
    }

    pub async fn publish_propagation_message(
        &self,
        topic: &str,
        message: p2p_proto::propagation::Message,
    ) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::PublishPropagationMessage {
                topic,
                message: message.into(),
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn send_sync_status_request(&self, peer_id: PeerId, status: p2p_proto::sync::Status) {
        self.sender
            .send(Command::SendSyncStatusRequest { peer_id, status })
            .await
            .expect("Command receiver not to be dropped");
    }

    #[cfg(test)]
    pub(crate) fn for_test(&self) -> test_utils::Client {
        test_utils::Client::new(self.sender.clone())
    }
}

type EmptyResultSender = oneshot::Sender<anyhow::Result<()>>;

#[derive(Debug)]
enum Command {
    StarListening {
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    Dial {
        peer_id: PeerId,
        addr: Multiaddr,
        sender: EmptyResultSender,
    },
    ProvideCapability {
        capability: String,
        sender: EmptyResultSender,
    },
    GetCapabilityProviders {
        capability: String,
        sender: mpsc::Sender<anyhow::Result<HashSet<PeerId>>>,
    },
    SubscribeTopic {
        topic: IdentTopic,
        sender: EmptyResultSender,
    },
    SendSyncRequest {
        peer_id: PeerId,
        request: p2p_proto::sync::Request,
        sender: oneshot::Sender<anyhow::Result<p2p_proto::sync::Response>>,
    },
    SendSyncStatusRequest {
        peer_id: PeerId,
        status: p2p_proto::sync::Status,
    },
    SendSyncResponse {
        channel: ResponseChannel<p2p_proto::sync::Response>,
        response: p2p_proto::sync::Response,
    },
    PublishPropagationMessage {
        topic: IdentTopic,
        message: Box<p2p_proto::propagation::Message>,
        sender: EmptyResultSender,
    },
    /// For testing purposes only
    _Test(TestCommand),
}

#[derive(Debug)]
pub enum TestCommand {
    GetPeersFromDHT(oneshot::Sender<HashSet<PeerId>>),
}

#[derive(Debug)]
pub enum Event {
    SyncPeerConnected {
        peer_id: PeerId,
    },
    SyncPeerRequestStatus {
        peer_id: PeerId,
    },
    InboundSyncRequest {
        from: PeerId,
        request: p2p_proto::sync::Request,
        channel: ResponseChannel<p2p_proto::sync::Response>,
    },
    BlockPropagation {
        from: PeerId,
        message: Box<p2p_proto::propagation::Message>,
    },
    /// For testing purposes only
    Test(TestEvent),
}

#[derive(Debug)]
pub enum TestEvent {
    NewListenAddress(Multiaddr),
    PeriodicBootstrapCompleted(Result<PeerId, PeerId>),
    StartProvidingCompleted(Result<Key, Key>),
    ConnectionEstablished { outbound: bool, remote: PeerId },
    Subscribed { remote: PeerId, topic: String },
    PeerAddedToDHT { remote: PeerId },
    Dummy,
}

pub type EventReceiver = mpsc::Receiver<Event>;

pub struct MainLoop {
    bootstrap_cfg: BootstrapConfig,
    swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,
    peers: Arc<RwLock<peers::Peers>>,
    pending_dials: HashMap<PeerId, EmptyResultSender>,
    pending_block_sync_requests:
        HashMap<RequestId, oneshot::Sender<anyhow::Result<p2p_proto::sync::Response>>>,
    pending_block_sync_status_requests: HashSet<RequestId>,
    request_sync_status: HashSetDelay<PeerId>,
    pending_queries: PendingQueries,
    _pending_test_queries: TestQueries,
}

#[derive(Debug, Default)]
struct PendingQueries {
    pub get_providers: HashMap<QueryId, mpsc::Sender<anyhow::Result<HashSet<PeerId>>>>,
}

impl MainLoop {
    fn new(
        swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
        peers: Arc<RwLock<peers::Peers>>,
        periodic_cfg: PeriodicTaskConfig,
    ) -> Self {
        Self {
            bootstrap_cfg: periodic_cfg.bootstrap,
            swarm,
            command_receiver,
            event_sender,
            peers,
            pending_dials: Default::default(),
            pending_block_sync_requests: Default::default(),
            pending_block_sync_status_requests: Default::default(),
            request_sync_status: HashSetDelay::new(periodic_cfg.status_period),
            pending_queries: Default::default(),
            _pending_test_queries: Default::default(),
        }
    }

    pub async fn run(mut self) {
        // Delay bootstrap so that by the time we attempt it we've connected to the bootstrap node
        let bootstrap_start = tokio::time::Instant::now() + self.bootstrap_cfg.start_offset;
        let mut bootstrap_interval =
            tokio::time::interval_at(bootstrap_start, self.bootstrap_cfg.period);

        let mut network_status_interval = tokio::time::interval(Duration::from_secs(5));
        let mut peer_status_interval = tokio::time::interval(Duration::from_secs(30));
        let me = *self.swarm.local_peer_id();

        loop {
            let bootstrap_interval_tick = bootstrap_interval.tick();
            tokio::pin!(bootstrap_interval_tick);

            let network_status_interval_tick = network_status_interval.tick();
            tokio::pin!(network_status_interval_tick);

            let peer_status_interval_tick = peer_status_interval.tick();
            tokio::pin!(peer_status_interval_tick);

            tokio::select! {
                _ = network_status_interval_tick => {
                    let network_info = self.swarm.network_info();
                    let num_peers = network_info.num_peers();
                    let connection_counters = network_info.connection_counters();
                    let num_established_connections = connection_counters.num_established();
                    let num_pending_connections = connection_counters.num_pending();
                    tracing::info!(%num_peers, %num_established_connections, %num_pending_connections, "Network status")
                }
                _ = peer_status_interval_tick => {
                    let dht = self.swarm.behaviour_mut().kademlia
                        .kbuckets()
                        // Cannot .into_iter() a KBucketRef, hence the inner collect followed by flat_map
                        .map(|kbucket_ref| {
                            kbucket_ref
                                .iter()
                                .map(|entry_ref| *entry_ref.node.key.preimage())
                                .collect::<Vec<_>>()
                        })
                        .flat_map(|peers_in_bucket| peers_in_bucket.into_iter())
                        .collect::<HashSet<_>>();
                    let guard = self.peers.read().await;
                    let connected = guard.connected().collect::<Vec<_>>();

                    tracing::info!(
                        "Peer status: me {}, connected {:?}, dht {:?}",
                        me,
                        connected,
                        dht,
                    );
                }
                _ = bootstrap_interval_tick => {
                    tracing::debug!("Doing periodical bootstrap");
                    _ = self.swarm.behaviour_mut().kademlia.bootstrap();
                }
                Some(Ok(peer_id)) = self.request_sync_status.next() => {
                    self.event_sender
                        .send(Event::SyncPeerRequestStatus { peer_id })
                        .await
                        .expect("Event receiver not to be dropped");
                }
                command = self.command_receiver.recv() => {
                    match command {
                        Some(c) => self.handle_command(c).await,
                        None => return,
                    }
                }
                Some(event) = self.swarm.next() => {
                    if let Err(e) = self.handle_event(event).await {
                        tracing::error!("event handling failed: {}", e);
                    }
                },
            }
        }
    }

    async fn handle_event<E: std::fmt::Debug>(
        &mut self,
        event: SwarmEvent<behaviour::Event, E>,
    ) -> anyhow::Result<()> {
        match event {
            // ===========================
            // Connection management
            // ===========================
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                self.peers.write().await.peer_connected(&peer_id);

                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_dials.remove(&peer_id) {
                        let _ = sender.send(Ok(()));
                        tracing::debug!(%peer_id, "Established outbound connection");
                    }
                    // FIXME else: trigger an error?
                } else {
                    tracing::debug!(%peer_id, "Established inbound connection");
                }

                send_test_event(
                    &self.event_sender,
                    TestEvent::ConnectionEstablished {
                        outbound: endpoint.is_dialer(),
                        remote: peer_id,
                    },
                )
                .await;

                Ok(())
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                if let Some(peer_id) = peer_id {
                    self.peers.write().await.peer_dial_error(&peer_id);

                    tracing::debug!(%peer_id, %error, "Error while dialing peer");

                    if let Some(sender) = self.pending_dials.remove(&peer_id) {
                        let _ = sender.send(Err(error.into()));
                    }
                }
                Ok(())
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    self.peers.write().await.peer_disconnected(&peer_id);
                    self.request_sync_status.remove(&peer_id);
                }
                tracing::debug!(%peer_id, "Disconnected from peer");
                Ok(())
            }
            SwarmEvent::Dialing(peer_id) => {
                self.peers.write().await.peer_dialing(&peer_id);
                tracing::debug!(%peer_id, "Dialing peer");
                Ok(())
            }
            // ===========================
            // Identify
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Identify(e)) => {
                if let identify::Event::Received {
                    peer_id,
                    info:
                        identify::Info {
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
                        for addr in &listen_addrs {
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, addr.clone());
                        }

                        if listen_addrs.is_empty() {
                            tracing::warn!(%peer_id, "Failed to add peer to DHT, no listening addresses");
                        } else {
                            tracing::debug!(%peer_id, "Added peer to DHT");
                        }
                    }

                    if protocols
                        .iter()
                        .any(|p| p.as_bytes() == sync::PROTOCOL_NAME)
                    {
                        self.trigger_periodic_sync_status(peer_id);
                        self.event_sender
                            .send(Event::SyncPeerConnected { peer_id })
                            .await
                            .expect("Event receiver not to be dropped");
                    }
                }
                Ok(())
            }
            // ===========================
            // Block propagation
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Gossipsub(gossipsub::Event::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            })) => {
                match p2p_proto::propagation::Message::from_protobuf_encoding(message.data.as_ref())
                {
                    Ok(decoded_message) => {
                        tracing::debug!(
                            "Gossipsub Event Message: [id={}][peer={}] {:?} ({} bytes)",
                            id,
                            peer_id,
                            decoded_message,
                            message.data.len()
                        );
                        self.event_sender
                            .send(Event::BlockPropagation {
                                from: peer_id,
                                message: decoded_message.into(),
                            })
                            .await?;
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to parse Gossipsub Message as Block Propagation: {}",
                            e
                        );
                    }
                }
                Ok(())
            }
            // ===========================
            // Discovery
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Kademlia(e)) => {
                match e {
                    KademliaEvent::OutboundQueryProgressed {
                        step, result, id, ..
                    } => {
                        if step.last {
                            match result {
                                libp2p::kad::QueryResult::Bootstrap(result) => {
                                    let network_info = self.swarm.network_info();
                                    let num_peers = network_info.num_peers();
                                    let connection_counters = network_info.connection_counters();
                                    let num_connections = connection_counters.num_connections();

                                    let result = match result {
                                        Ok(BootstrapOk { peer, .. }) => {
                                            tracing::debug!(%num_peers, %num_connections, "Periodic bootstrap completed");
                                            Ok(peer)
                                        }
                                        Err(BootstrapError::Timeout { peer, .. }) => {
                                            tracing::warn!(%num_peers, %num_connections, "Periodic bootstrap failed");
                                            Err(peer)
                                        }
                                    };
                                    send_test_event(
                                        &self.event_sender,
                                        TestEvent::PeriodicBootstrapCompleted(result),
                                    )
                                    .await;
                                }
                                QueryResult::GetProviders(result) => {
                                    use libp2p::kad::GetProvidersOk;

                                    let result = match result {
                                        Ok(GetProvidersOk::FoundProviders {
                                            providers, ..
                                        }) => Ok(providers),
                                        Ok(GetProvidersOk::FinishedWithNoAdditionalRecord {
                                            ..
                                        }) => Ok(Default::default()),
                                        Err(e) => Err(e.into()),
                                    };

                                    let sender = self
                                        .pending_queries
                                        .get_providers
                                        .remove(&id)
                                        .expect("Query to be pending");

                                    sender
                                        .send(result)
                                        .await
                                        .expect("Receiver not to be dropped");
                                }
                                _ => self.test_query_completed(id, result).await,
                            }
                        } else if let QueryResult::GetProviders(result) = result {
                            use libp2p::kad::GetProvidersOk;

                            let result = match result {
                                Ok(GetProvidersOk::FoundProviders { providers, .. }) => {
                                    Ok(providers)
                                }
                                Ok(_) => Ok(Default::default()),
                                Err(_) => {
                                    unreachable!(
                                        "when a query times out libp2p makes it the last stage"
                                    )
                                }
                            };

                            let sender = self
                                .pending_queries
                                .get_providers
                                .get(&id)
                                .expect("Query to be pending");

                            sender
                                .send(result)
                                .await
                                .expect("Receiver not to be dropped");
                        } else {
                            self.test_query_progressed(id, result).await;
                        }
                    }
                    KademliaEvent::RoutingUpdated {
                        peer, is_new_peer, ..
                    } => {
                        if is_new_peer {
                            send_test_event(
                                &self.event_sender,
                                TestEvent::PeerAddedToDHT { remote: peer },
                            )
                            .await
                        }
                    }
                    _ => {}
                }

                Ok(())
            }
            // ===========================
            // Block sync
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::BlockSync(
                request_response::Event::Message { message, peer },
            )) => {
                match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        tracing::debug!(?request, %peer, "Received block sync request");

                        // received an incoming status request, update peer state
                        if let p2p_proto::sync::Request::Status(status) = &request {
                            self.peers
                                .write()
                                .await
                                .update_sync_status(&peer, status.clone());
                            self.trigger_periodic_sync_status(peer);
                        }

                        self.event_sender
                            .send(Event::InboundSyncRequest {
                                from: peer,
                                request,
                                channel,
                            })
                            .await
                            .expect("Event receiver not to be dropped");
                        Ok(())
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        if self.pending_block_sync_status_requests.remove(&request_id) {
                            // this was a status response, handle this internally
                            if let p2p_proto::sync::Response::Status(status) = response {
                                self.peers.write().await.update_sync_status(&peer, status);
                                Ok(())
                            } else {
                                Err(anyhow::anyhow!(
                                    "Expected a status response for a status request"
                                ))
                            }
                        } else {
                            // a "normal" response
                            let _ = self
                                .pending_block_sync_requests
                                .remove(&request_id)
                                .expect("Block sync request still to be pending")
                                .send(Ok(response));
                            Ok(())
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(behaviour::Event::BlockSync(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                if !self.pending_block_sync_status_requests.remove(&request_id) {
                    let _ = self
                        .pending_block_sync_requests
                        .remove(&request_id)
                        .expect("Block sync request still to be pending")
                        .send(Err(error.into()));
                }
                Ok(())
            }
            // ===========================
            // NAT hole punching
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::Dcutr(event)) => {
                tracing::debug!(?event, "DCUtR event");
                Ok(())
            }
            // ===========================
            // Ignored or forwarded for
            // test purposes
            // ===========================
            event => {
                match &event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        let my_peerid = *self.swarm.local_peer_id();
                        let address = address.clone().with(Protocol::P2p(my_peerid.into()));

                        tracing::debug!(%address, "New listen");
                    }
                    _ => tracing::trace!(?event, "Ignoring event"),
                }
                self.handle_event_for_test(event).await;
                Ok(())
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::StarListening { addr, sender } => {
                let _ = match self.swarm.listen_on(addr.clone()) {
                    Ok(_) => {
                        tracing::debug!(%addr, "Started listening");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e.into())),
                };
            }
            Command::Dial {
                peer_id,
                addr,
                sender,
            } => {
                if let std::collections::hash_map::Entry::Vacant(e) =
                    self.pending_dials.entry(peer_id)
                {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    match self.swarm.dial(addr.clone()) {
                        Ok(_) => {
                            tracing::debug!(%addr, "Dialed peer");
                            e.insert(sender);
                        }
                        Err(e) => {
                            let _ = sender.send(Err(e.into()));
                        }
                    };
                } else {
                    let _ = sender.send(Err(anyhow::anyhow!("Dialing is already pending")));
                }
            }
            Command::ProvideCapability { capability, sender } => {
                let _ = match self.swarm.behaviour_mut().provide_capability(&capability) {
                    Ok(_) => {
                        tracing::debug!(%capability, "Providing capability");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e)),
                };
            }
            Command::GetCapabilityProviders { capability, sender } => {
                let query_id = self
                    .swarm
                    .behaviour_mut()
                    .get_capability_providers(&capability);
                self.pending_queries.get_providers.insert(query_id, sender);
            }
            Command::SubscribeTopic { topic, sender } => {
                let _ = match self.swarm.behaviour_mut().subscribe_topic(&topic) {
                    Ok(_) => {
                        tracing::debug!(%topic, "Subscribing to topic");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e)),
                };
            }
            Command::SendSyncRequest {
                peer_id,
                request,
                sender,
            } => {
                tracing::debug!(?request, "Sending sync request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_request(&peer_id, request);
                self.pending_block_sync_requests.insert(request_id, sender);
            }
            Command::SendSyncResponse { channel, response } => {
                // This might fail, but we're just ignoring it. In case of failure a
                // RequestResponseEvent::InboundFailure will or has been be emitted.
                tracing::debug!(%response, "Sending sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_response(channel, response);
            }
            Command::SendSyncStatusRequest { peer_id, status } => {
                tracing::debug!(?status, "Sending sync status request");

                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_request(&peer_id, p2p_proto::sync::Request::Status(status));
                self.pending_block_sync_status_requests.insert(request_id);
                self.trigger_periodic_sync_status(peer_id);
            }
            Command::PublishPropagationMessage {
                topic,
                message,
                sender,
            } => {
                let data: Vec<u8> = message.into_protobuf_encoding();
                let result = self.publish_data(topic, &data);
                let _ = sender.send(result);
            }
            Command::_Test(command) => self.handle_test_command(command).await,
        };
    }

    fn publish_data(&mut self, topic: IdentTopic, data: &[u8]) -> anyhow::Result<()> {
        let message_id = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)
            .map_err(|e| anyhow::anyhow!("Gossipsub publish failed: {}", e))?;
        tracing::debug!(?message_id, "Data published");
        Ok(())
    }

    fn trigger_periodic_sync_status(&mut self, peer_id: PeerId) {
        let local_peer_id = self.swarm.local_peer_id();
        if local_peer_id < &peer_id {
            self.request_sync_status.insert(peer_id);
        }
    }

    /// No-op outside tests
    async fn handle_event_for_test<E: std::fmt::Debug>(
        &mut self,
        _event: SwarmEvent<behaviour::Event, E>,
    ) {
        #[cfg(test)]
        test_utils::handle_event(&self.event_sender, _event).await
    }

    /// No-op outside tests
    async fn handle_test_command(&mut self, _command: TestCommand) {
        #[cfg(test)]
        test_utils::handle_command(
            self.swarm.behaviour_mut(),
            _command,
            &mut self._pending_test_queries.inner,
        )
        .await;
    }

    /// Handle the final stage of the query, no-op outside tests
    async fn test_query_completed(&mut self, _id: QueryId, _result: QueryResult) {
        #[cfg(test)]
        test_utils::query_completed(
            &mut self._pending_test_queries.inner,
            &self.event_sender,
            _id,
            _result,
        )
        .await;
    }

    /// Handle all stages except the final one, no-op outside tests
    async fn test_query_progressed(&mut self, _id: QueryId, _result: QueryResult) {
        #[cfg(test)]
        test_utils::query_progressed(&self._pending_test_queries.inner, _id, _result).await
    }
}

/// No-op outside tests
async fn send_test_event(_event_sender: &mpsc::Sender<Event>, _event: TestEvent) {
    #[cfg(test)]
    test_utils::send_event(_event_sender, _event).await
}

#[derive(Debug, Default)]
struct TestQueries {
    #[cfg(test)]
    inner: test_utils::PendingQueries,
}
