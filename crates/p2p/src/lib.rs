#![deny(rust_2018_idioms)]

use std::time::Duration;

use futures::channel::mpsc;
use futures::stream::Stream;
use futures::StreamExt;
use libp2p::gossipsub::IdentTopic;
use libp2p::identify;
use libp2p::identity::Keypair;
use libp2p::kad::{self, KademliaEvent};
use libp2p::swarm::{SwarmBuilder, SwarmEvent};
use libp2p::Multiaddr;

mod behaviour;
mod executor;
mod transport;

pub fn new(
    keypair: Keypair,
    listen_on: Multiaddr,
    bootstrap_addresses: Vec<Multiaddr>,
    capabilities: &[&str],
    chain_id: u128,
) -> anyhow::Result<(Client, impl Stream<Item = Event>, MainLoop)> {
    let peer_id = keypair.public().to_peer_id();

    let mut swarm = SwarmBuilder::new(
        transport::create(&keypair),
        behaviour::Behaviour::new(&keypair, capabilities),
        peer_id,
    )
    .executor(Box::new(executor::TokioExecutor()))
    .build();

    swarm.listen_on(listen_on)?;

    for bootstrap_address in bootstrap_addresses {
        swarm.dial(bootstrap_address)?;
    }

    let block_propagation_topic = IdentTopic::new(format!("blocks/{}", chain_id));
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_propagation_topic)?;

    let (command_sender, command_receiver) = mpsc::channel(0);
    let (event_sender, event_receiver) = mpsc::channel(0);

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

#[derive(Debug)]
pub enum Command {
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
                command = self.command_receiver.next() => {
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

    async fn handle_command(&mut self, _command: Command) {}
}
