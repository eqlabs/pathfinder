use std::time::Duration;

use libp2p::identify;
use libp2p::kad::{record::store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent};
use libp2p::ping;
use libp2p::{identity, NetworkBehaviour};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "BootstrapEvent", event_process = false)]
pub struct BootstrapBehaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub kademlia: Kademlia<MemoryStore>,
}

impl BootstrapBehaviour {
    pub fn new(pub_key: identity::PublicKey) -> Self {
        const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(600);
        // FIXME: clarify what version number should be
        // FIXME: we're also missing the starting '/'
        const PROTOCOL_VERSION: &str = "starknet/0.9.1";

        const KADEMLIA_PROTOCOL_NAME: &[u8] = b"/pathfinder/kad/1.0.0";

        let mut kademlia_config = KademliaConfig::default();
        kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
        kademlia_config.set_provider_record_ttl(Some(PROVIDER_PUBLICATION_INTERVAL * 3));
        kademlia_config.set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));
        // FIXME: this make sure that the DHT we're implementing is incompatible with the "default" IPFS
        // DHT from libp2p.
        kademlia_config
            .set_protocol_names(vec![std::borrow::Cow::Borrowed(KADEMLIA_PROTOCOL_NAME)]);

        let kademlia = Kademlia::with_config(
            pub_key.to_peer_id(),
            MemoryStore::new(pub_key.to_peer_id()),
            kademlia_config,
        );

        Self {
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(PROTOCOL_VERSION.to_string(), pub_key)
                    .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia,
        }
    }
}

#[derive(Debug)]
pub enum BootstrapEvent {
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Kademlia(KademliaEvent),
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

impl From<KademliaEvent> for BootstrapEvent {
    fn from(event: KademliaEvent) -> Self {
        BootstrapEvent::Kademlia(event)
    }
}
