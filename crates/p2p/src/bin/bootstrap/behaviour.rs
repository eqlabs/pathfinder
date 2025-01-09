use std::time::Duration;

use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{autonat, dcutr, identify, identity, ping, relay};
use p2p::kademlia_protocol_name;
use pathfinder_common::ChainId;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BootstrapEvent", event_process = false)]
pub struct BootstrapBehaviour {
    relay: relay::Behaviour,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
}

impl BootstrapBehaviour {
    pub fn new(pub_key: identity::PublicKey, chain_id: ChainId) -> Self {
        const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(600);

        let mut kademlia_config = kad::Config::new(kademlia_protocol_name(chain_id));
        kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
        kademlia_config.set_provider_record_ttl(Some(PROVIDER_PUBLICATION_INTERVAL * 3));
        kademlia_config.set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));

        let kademlia = kad::Behaviour::with_config(
            pub_key.to_peer_id(),
            MemoryStore::new(pub_key.to_peer_id()),
            kademlia_config,
        );

        let peer_id = pub_key.to_peer_id();

        Self {
            relay: relay::Behaviour::new(peer_id, Default::default()),
            autonat: autonat::Behaviour::new(peer_id, Default::default()),
            dcutr: dcutr::Behaviour::new(peer_id),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(identify::PROTOCOL_NAME.to_string(), pub_key)
                    .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum BootstrapEvent {
    Relay(relay::Event),
    Autonat(autonat::Event),
    Dcutr(dcutr::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Kademlia(kad::Event),
}

impl From<relay::Event> for BootstrapEvent {
    fn from(event: relay::Event) -> Self {
        BootstrapEvent::Relay(event)
    }
}

impl From<autonat::Event> for BootstrapEvent {
    fn from(event: autonat::Event) -> Self {
        BootstrapEvent::Autonat(event)
    }
}

impl From<dcutr::Event> for BootstrapEvent {
    fn from(event: dcutr::Event) -> Self {
        BootstrapEvent::Dcutr(event)
    }
}

impl From<ping::Event> for BootstrapEvent {
    fn from(event: ping::Event) -> Self {
        BootstrapEvent::Ping(event)
    }
}

impl From<identify::Event> for BootstrapEvent {
    fn from(event: identify::Event) -> Self {
        BootstrapEvent::Identify(Box::new(event))
    }
}

impl From<kad::Event> for BootstrapEvent {
    fn from(event: kad::Event) -> Self {
        BootstrapEvent::Kademlia(event)
    }
}
