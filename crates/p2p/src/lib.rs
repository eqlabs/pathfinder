#![deny(rust_2018_idioms)]

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use delay_map::HashSetDelay;
use futures::StreamExt;
use libp2p::gossipsub::{GossipsubEvent, IdentTopic};
use libp2p::identity::Keypair;
use libp2p::kad::KademliaEvent;
use libp2p::request_response::{
    RequestId, RequestResponseEvent, RequestResponseMessage, ResponseChannel,
};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;
use libp2p::{identify, PeerId};
use tokio::sync::{mpsc, oneshot, RwLock};

mod behaviour;
mod executor;
mod peers;
mod sync;
#[cfg(test)]
mod tests;
mod transport;

pub use peers::Peers;

pub use libp2p;

pub fn new(
    keypair: Keypair,
    peers: Arc<RwLock<peers::Peers>>,
    periodic_status_interval: Duration,
) -> (Client, EventReceiver, MainLoop) {
    let peer_id = keypair.public().to_peer_id();

    let (behaviour, relay_transport) = behaviour::Behaviour::new(&keypair);

    let swarm = SwarmBuilder::with_executor(
        transport::create(&keypair, relay_transport),
        behaviour,
        peer_id,
        executor::TokioExecutor(),
    )
    .build();

    let (command_sender, command_receiver) = mpsc::channel(1);
    let (event_sender, event_receiver) = mpsc::channel(1);

    (
        Client {
            sender: command_sender,
        },
        event_receiver,
        MainLoop::new(
            swarm,
            command_receiver,
            event_sender,
            peers,
            periodic_status_interval,
        ),
    )
}

#[derive(Clone)]
pub struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    pub async fn start_listening(&mut self, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::StarListening { addr, sender })
            .await
            .expect("Command receiver not to be dropped.");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn dial(&mut self, peer_id: PeerId, addr: Multiaddr) -> anyhow::Result<()> {
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

    pub async fn provide_capability(&mut self, capability: &str) -> anyhow::Result<()> {
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

    pub async fn subscribe_topic(&mut self, topic: &str) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::SubscribeTopic { topic, sender })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn send_sync_request(
        &mut self,
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
        &mut self,
        channel: ResponseChannel<p2p_proto::sync::Response>,
        response: p2p_proto::sync::Response,
    ) {
        self.sender
            .send(Command::SendSyncResponse { channel, response })
            .await
            .expect("Command receiver not to be dropped");
    }

    pub async fn publish_propagation_message(
        &mut self,
        topic: &str,
        message: p2p_proto::propagation::Message,
    ) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::PublishPropagationMessage {
                topic,
                message,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn send_sync_status_request(
        &mut self,
        peer_id: PeerId,
        status: p2p_proto::sync::Status,
    ) {
        self.sender
            .send(Command::SendSyncStatusRequest { peer_id, status })
            .await
            .expect("Command receiver not to be dropped");
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
        message: p2p_proto::propagation::Message,
        sender: EmptyResultSender,
    },
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
    BlockPropagation(p2p_proto::propagation::Message),
    /// For testing purposes only
    Test(TestEvent),
}

#[derive(Debug)]
pub enum TestEvent {
    NewListenAddress(Multiaddr),
    Dummy,
}

pub type EventReceiver = mpsc::Receiver<Event>;

pub struct MainLoop {
    swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,

    peers: Arc<RwLock<peers::Peers>>,

    pending_dials: HashMap<PeerId, EmptyResultSender>,
    pending_block_sync_requests:
        HashMap<RequestId, oneshot::Sender<anyhow::Result<p2p_proto::sync::Response>>>,
    pending_block_sync_status_requests: HashSet<RequestId>,

    request_sync_status: HashSetDelay<PeerId>,
}

impl MainLoop {
    fn new(
        swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
        peers: Arc<RwLock<peers::Peers>>,
        periodic_status_interval: Duration,
    ) -> Self {
        Self {
            swarm,
            command_receiver,
            event_sender,
            peers,
            pending_dials: Default::default(),
            pending_block_sync_requests: Default::default(),
            pending_block_sync_status_requests: Default::default(),
            request_sync_status: HashSetDelay::new(periodic_status_interval),
        }
    }

    pub async fn run(mut self) {
        const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(10 * 60);
        // delay bootstrap so that by the time we attempt it we've connected to the bootstrap node
        let bootstrap_start = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut bootstrap_interval = tokio::time::interval_at(bootstrap_start, BOOTSTRAP_INTERVAL);

        loop {
            let bootstrap_interval_tick = bootstrap_interval.tick();
            tokio::pin!(bootstrap_interval_tick);

            tokio::select! {
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
                } else {
                    tracing::debug!(%peer_id, "Established inbound connection");
                }
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
                        tracing::debug!(%peer_id, "Added peer to DHT");
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
            SwarmEvent::Behaviour(behaviour::Event::Gossipsub(GossipsubEvent::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            })) => {
                match p2p_proto::propagation::Message::from_protobuf_encoding(message.data.as_ref())
                {
                    Ok(event) => {
                        tracing::debug!(
                            "Gossipsub Event Message: [id={}][peer={}] {:?} ({} bytes)",
                            id,
                            peer_id,
                            event,
                            message.data.len()
                        );
                        self.event_sender
                            .send(Event::BlockPropagation(event))
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
                if let KademliaEvent::OutboundQueryProgressed { step, .. } = e {
                    if step.last {
                        let network_info = self.swarm.network_info();
                        let num_peers = network_info.num_peers();
                        let connection_counters = network_info.connection_counters();
                        let num_connections = connection_counters.num_connections();
                        tracing::debug!(%num_peers, %num_connections, "Periodic bootstrap completed");
                    }
                }
                Ok(())
            }
            // ===========================
            // Block sync
            // ===========================
            SwarmEvent::Behaviour(behaviour::Event::BlockSync(RequestResponseEvent::Message {
                message,
                peer,
            })) => {
                match message {
                    RequestResponseMessage::Request {
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
                    RequestResponseMessage::Response {
                        request_id,
                        response,
                    } => {
                        tracing::debug!(?response, %peer, "Received block sync response");
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
                RequestResponseEvent::OutboundFailure {
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
            event => self.ignore_or_handle_event_for_test(event).await,
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
                tracing::debug!(?request, "Sending block sync request");

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
                tracing::debug!(?response, "Sending block sync response");

                let _ = self
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_response(channel, response);
            }
            Command::SendSyncStatusRequest { peer_id, status } => {
                tracing::debug!(?status, "Sending block sync status");

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

    #[cfg(not(test))]
    async fn ignore_or_handle_event_for_test<E: std::fmt::Debug>(
        &mut self,
        event: SwarmEvent<behaviour::Event, E>,
    ) -> anyhow::Result<()> {
        tracing::trace!(?event, "Ignoring event");
        Ok(())
    }

    #[cfg(test)]
    async fn ignore_or_handle_event_for_test<E: std::fmt::Debug>(
        &mut self,
        event: SwarmEvent<behaviour::Event, E>,
    ) -> anyhow::Result<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                self.event_sender
                    .send(Event::Test(TestEvent::NewListenAddress(address)))
                    .await?;
                Ok(())
            }
            _ => {
                tracing::trace!(?event, "Ignoring event");
                Ok(())
            }
        }
    }
}
