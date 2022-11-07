#![deny(rust_2018_idioms)]

use std::time::Duration;

use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use libp2p::identify;
use libp2p::identity::Keypair;
use libp2p::kad::{self, KademliaEvent};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

mod behaviour;
mod executor;
mod transport;

pub fn new(
    keypair: Keypair,
    capabilities: &[&str],
    chain_id: u128,
) -> anyhow::Result<(Client, mpsc::Receiver<Event>, MainLoop)> {
    let peer_id = keypair.public().to_peer_id();

    let mut swarm = SwarmBuilder::new(
        transport::create(&keypair),
        behaviour::Behaviour::new(&keypair, capabilities),
        peer_id,
    )
    .executor(Box::new(executor::TokioExecutor()))
    .build();

    let block_propagation_topic = IdentTopic::new(format!("blocks/{}", chain_id));
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_propagation_topic)?;

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
}

#[derive(Debug)]
pub enum Command {
    StarListening {
        addr: Multiaddr,
        sender: oneshot::Sender<anyhow::Result<()>>,
    },
    Dial {
        addr: Multiaddr,
        sender: oneshot::Sender<anyhow::Result<()>>,
    },
    RequestBlockHeader,
}

#[derive(Debug)]
pub enum Event {
    InboundRequestBlockHeader,
}

pub struct MainLoop {
    swarm: libp2p::swarm::Swarm<behaviour::Behaviour>,
    command_receiver: mpsc::Receiver<Command>,
    event_sender: mpsc::Sender<Event>,
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
                        for addr in listen_addrs {
                            self.swarm
                                .behaviour_mut()
                                .kademlia
                                .add_address(&peer_id, addr);
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
            _ => {}
        };
    }
}
