#![deny(rust_2018_idioms)]

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
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

mod behaviour;
mod executor;
mod sync;
mod transport;

pub fn new(keypair: Keypair) -> anyhow::Result<(Client, mpsc::Receiver<Event>, MainLoop)> {
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

    Ok((
        Client {
            sender: command_sender,
        },
        event_receiver,
        MainLoop::new(swarm, command_receiver, event_sender),
    ))
}

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

    pub async fn get_sync_peer(&mut self) -> Option<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::GetSyncPeer { sender })
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
    GetSyncPeer {
        sender: oneshot::Sender<Option<PeerId>>,
    },
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
                Some(event) = self.swarm.next() => self.handle_event(event).await,
            }
        }
    }

    async fn handle_event<E: std::fmt::Debug>(&mut self, event: SwarmEvent<behaviour::Event, E>) {
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
            }
            SwarmEvent::Behaviour(behaviour::Event::Gossipsub(e)) => {
                tracing::info!(?e, "Gossipsub event");
            }
            SwarmEvent::Behaviour(behaviour::Event::Kademlia(e)) => {
                if let KademliaEvent::OutboundQueryCompleted { .. } = e {
                    let network_info = self.swarm.network_info();
                    let num_peers = network_info.num_peers();
                    let connection_counters = network_info.connection_counters();
                    let num_connections = connection_counters.num_connections();
                    tracing::debug!(%num_peers, %num_connections, "Periodic bootstrap completed")
                }
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
                    }
                }
            }
            SwarmEvent::Behaviour(behaviour::Event::BlockSync(
                RequestResponseEvent::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                let _ = self
                    .pending_block_sync_requests
                    .remove(&request_id)
                    .expect("Block sync request still to be pending")
                    .send(Err(error.into()));
            }
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                tracing::debug!(%peer_id, "Connected to peer");
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.peers.remove(&peer_id);
                tracing::debug!(%peer_id, "Disconnected from peer");
            }
            event => {
                tracing::trace!(?event, "Ignoring event");
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
            Command::GetSyncPeer { sender } => {
                let maybe_peer_id = self.peers.keys().cloned().next();
                let _ = sender.send(maybe_peer_id);
            }
        };
    }
}
