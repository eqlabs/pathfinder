#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::{GossipsubEvent, IdentTopic};
use libp2p::identity::Keypair;
use libp2p::kad::{self, KademliaEvent};
use libp2p::request_response::{
    RequestId, RequestResponseEvent, RequestResponseMessage, ResponseChannel,
};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;
use libp2p::{identify, PeerId};
use tokio::sync::mpsc;
use tokio::sync::oneshot;

use p2p_proto::proto::propagation::{NewBlockBody, NewBlockHeader, NewBlockState};

mod behaviour;
mod executor;
mod sync;
mod transport;

pub fn new(keypair: Keypair) -> (Client, mpsc::Receiver<Event>, MainLoop) {
    let peer_id = keypair.public().to_peer_id();

    let swarm = SwarmBuilder::new(
        transport::create(&keypair),
        behaviour::Behaviour::new(&keypair),
        peer_id,
    )
    .executor(Box::new(executor::TokioExecutor()))
    .build();

    let (command_sender, command_receiver) = mpsc::channel(1);
    let (event_sender, event_receiver) = mpsc::channel(1);

    (
        Client {
            sender: command_sender,
        },
        event_receiver,
        MainLoop::new(swarm, command_receiver, event_sender),
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

    pub async fn dial(&mut self, addr: Multiaddr) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::Dial { addr, sender })
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

    pub async fn get_sync_peer(&mut self) -> Option<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::GetSyncPeer { sender })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn publish_event(&mut self, topic: &str, event: Event) -> anyhow::Result<()> {
        let (sender, receiver) = oneshot::channel();
        let topic = IdentTopic::new(topic);
        self.sender
            .send(Command::PublishEvent {
                event,
                topic,
                sender,
            })
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
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
    SendSyncResponse {
        channel: ResponseChannel<p2p_proto::sync::Response>,
        response: p2p_proto::sync::Response,
    },
    GetSyncPeer {
        sender: oneshot::Sender<Option<PeerId>>,
    },
    PublishEvent {
        topic: IdentTopic,
        sender: EmptyResultSender,
        event: Event,
    },
}

#[derive(Debug)]
pub enum BlockPropagation {
    NewBlockHeader(NewBlockHeader),
    NewBlockBody(NewBlockBody),
    NewBlockState(NewBlockState),
}

impl TryFrom<&[u8]> for BlockPropagation {
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self, Self::Error> {
        if let Ok(new_block_header) = prost::Message::decode(buf)
            .map_err(|e| anyhow::anyhow!("BlockPropagation decode failed: {}", e))
        {
            return Ok(BlockPropagation::NewBlockHeader(new_block_header));
        }

        if let Ok(new_block_body) = prost::Message::decode(buf)
            .map_err(|e| anyhow::anyhow!("BlockPropagation decode failed: {}", e))
        {
            return Ok(BlockPropagation::NewBlockBody(new_block_body));
        }

        if let Ok(new_block_state) = prost::Message::decode(buf)
            .map_err(|e| anyhow::anyhow!("BlockPropagation decode failed: {}", e))
        {
            return Ok(BlockPropagation::NewBlockState(new_block_state));
        }

        Err(anyhow::anyhow!("BlockPropagation decoding failed"))
    }
}

impl From<BlockPropagation> for Vec<u8> {
    fn from(value: BlockPropagation) -> Self {
        use prost::Message;
        match value {
            BlockPropagation::NewBlockHeader(new_block_header) => new_block_header.encode_to_vec(),
            BlockPropagation::NewBlockBody(new_block_body) => new_block_body.encode_to_vec(),
            BlockPropagation::NewBlockState(new_block_state) => new_block_state.encode_to_vec(),
        }
    }
}

#[derive(Debug)]
pub enum Event {
    SyncPeerConnected {
        peer_id: PeerId,
    },
    InboundSyncRequest {
        request: p2p_proto::sync::Request,
        channel: ResponseChannel<p2p_proto::sync::Response>,
    },
    BlockPropagation(BlockPropagation),
}

pub struct MainLoop {
    swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,

    peers: HashMap<PeerId, Peer>,

    pending_block_sync_requests:
        HashMap<RequestId, oneshot::Sender<anyhow::Result<p2p_proto::sync::Response>>>,
}

pub struct Peer {
    pub listening_addresses: Vec<Multiaddr>,
}

impl MainLoop {
    fn new(
        swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
        command_receiver: mpsc::Receiver<Command>,
        event_sender: mpsc::Sender<Event>,
    ) -> Self {
        Self {
            swarm,
            command_receiver,
            event_sender,
            peers: Default::default(),
            pending_block_sync_requests: Default::default(),
        }
    }

    pub async fn run(mut self) {
        const BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(30);
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
                        .any(|p| p.as_bytes() == kad::protocol::DEFAULT_PROTO_NAME)
                    {
                        for addr in &listen_addrs {
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, addr.clone());
                        }

                        // add to peers if seems useful
                        if protocols
                            .iter()
                            .any(|p| p.as_bytes() == sync::PROTOCOL_NAME)
                        {
                            self.peers.insert(
                                peer_id,
                                Peer {
                                    listening_addresses: listen_addrs,
                                },
                            );
                            self.event_sender
                                .send(Event::SyncPeerConnected { peer_id })
                                .await
                                .expect("Event receiver not to be dropped");
                        }
                        tracing::debug!(%peer_id, "Added peer to DHT");
                    }
                }
                Ok(())
            }
            SwarmEvent::Behaviour(behaviour::Event::Gossipsub(GossipsubEvent::Message {
                propagation_source: peer_id,
                message_id: id,
                message,
            })) => {
                match BlockPropagation::try_from(message.data.as_ref()) {
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
            SwarmEvent::Behaviour(behaviour::Event::Kademlia(e)) => {
                if let KademliaEvent::OutboundQueryCompleted { .. } = e {
                    let network_info = self.swarm.network_info();
                    let num_peers = network_info.num_peers();
                    let connection_counters = network_info.connection_counters();
                    let num_connections = connection_counters.num_connections();
                    tracing::debug!(%num_peers, %num_connections, "Periodic bootstrap completed");
                }
                Ok(())
            }
            SwarmEvent::Behaviour(behaviour::Event::BlockSync(RequestResponseEvent::Message {
                message,
                peer,
            })) => {
                tracing::trace!(%peer, "Received a message");
                match message {
                    RequestResponseMessage::Request {
                        request, channel, ..
                    } => {
                        self.event_sender
                            .send(Event::InboundSyncRequest { request, channel })
                            .await
                            .expect("Event receiver not to be dropped");
                        Ok(())
                    }
                    RequestResponseMessage::Response {
                        request_id,
                        response,
                    } => {
                        let _ = self
                            .pending_block_sync_requests
                            .remove(&request_id)
                            .expect("Block sync request still to be pending")
                            .send(Ok(response));
                        Ok(())
                    }
                }
            }
            SwarmEvent::Behaviour(behaviour::Event::BlockSync(
                RequestResponseEvent::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                tracing::warn!(?request_id, ?error, "Outbound request failed");
                let _ = self
                    .pending_block_sync_requests
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
                Ok(())
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::debug!(%peer_id, "Connected to peer");
                Ok(())
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.peers.remove(&peer_id);
                tracing::debug!(%peer_id, "Disconnected from peer");
                Ok(())
            }
            event => {
                tracing::trace!(?event, "Ignoring event");
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
            Command::Dial { addr, sender } => {
                let _ = match self.swarm.dial(addr.clone()) {
                    Ok(_) => {
                        tracing::debug!(%addr, "Dialed peer");
                        sender.send(Ok(()))
                    }
                    Err(e) => sender.send(Err(e.into())),
                };
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
                        tracing::debug!(%topic, "Providing capability");
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
                let response = self
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_response(channel, response);
                tracing::warn!(?response, "Sent response");
            }
            Command::GetSyncPeer { sender } => {
                let maybe_peer_id = self.peers.keys().cloned().next();
                let _ = sender.send(maybe_peer_id);
            }
            Command::PublishEvent {
                event: Event::BlockPropagation(block_propagation),
                topic,
                sender,
            } => {
                let data: Vec<u8> = block_propagation.into();
                let result = self.publish_data(topic, &data);
                let _ = sender.send(result);
            }
            _ => {
                tracing::warn!(?command, "Unexpected command");
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
}
