use std::time::Duration;

use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::{record::store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent};
use libp2p::ping::{Ping, PingConfig, PingEvent};
use libp2p::{identity, NetworkBehaviour};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "BootstrapEvent", event_process = false)]
pub struct BootstrapBehaviour {
    ping: Ping,
    identify: Identify,
    pub kademlia: Kademlia<MemoryStore>,
}

impl BootstrapBehaviour {
    pub fn new(pub_key: identity::PublicKey) -> Self {
        const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(600);
        // FIXME: clarify what version number should be
        // FIXME: we're also missing the staring '/'
        const PROTOCOL_VERSION: &str = "starknet/0.9.1";

        let mut kademlia_config = KademliaConfig::default();
        kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
        kademlia_config.set_provider_record_ttl(Some(PROVIDER_PUBLICATION_INTERVAL * 3));
        kademlia_config.set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));

        let kademlia = Kademlia::with_config(
            pub_key.to_peer_id(),
            MemoryStore::new(pub_key.to_peer_id()),
            kademlia_config,
        );

        Self {
            ping: Ping::new(PingConfig::new()),
            identify: Identify::new(
                IdentifyConfig::new(PROTOCOL_VERSION.to_string(), pub_key)
                    .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia,
        }
    }
}

#[derive(Debug)]
pub enum BootstrapEvent {
    Ping(PingEvent),
    Identify(Box<IdentifyEvent>),
    Kademlia(KademliaEvent),
}

impl From<PingEvent> for BootstrapEvent {
    fn from(event: PingEvent) -> Self {
        BootstrapEvent::Ping(event)
    }
}

impl From<IdentifyEvent> for BootstrapEvent {
    fn from(event: IdentifyEvent) -> Self {
        BootstrapEvent::Identify(Box::new(event))
    }
}

impl From<KademliaEvent> for BootstrapEvent {
    fn from(event: KademliaEvent) -> Self {
        BootstrapEvent::Kademlia(event)
    }
}
