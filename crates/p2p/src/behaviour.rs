use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::gossipsub::{
    Gossipsub, GossipsubEvent, GossipsubMessage, MessageAuthenticity, MessageId,
};
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::{record::store::MemoryStore, Kademlia, KademliaConfig, KademliaEvent};
use libp2p::ping::{Ping, PingConfig, PingEvent};
use libp2p::{identity, kad, NetworkBehaviour};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", event_process = false)]
pub struct Behaviour {
    ping: Ping,
    identify: Identify,
    pub kademlia: Kademlia<MemoryStore>,
    pub gossipsub: Gossipsub,
}

impl Behaviour {
    pub fn new(identity: &identity::Keypair, capabilities: &[&str]) -> Self {
        const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(600);
        // FIXME: clarify what version number should be
        // FIXME: we're also missing the staring '/'
        const PROTOCOL_VERSION: &str = "starknet/0.9.1";

        let mut kademlia_config = KademliaConfig::default();
        kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
        kademlia_config.set_provider_record_ttl(Some(PROVIDER_PUBLICATION_INTERVAL * 3));
        kademlia_config.set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));

        let peer_id = identity.public().to_peer_id();

        let mut kademlia =
            Kademlia::with_config(peer_id, MemoryStore::new(peer_id), kademlia_config);

        for capability in capabilities {
            let key = string_to_key(capability);
            kademlia
                .start_providing(key)
                .expect("Providing capability should not fail");
        }

        // FIXME: find out how we should derive message id
        let message_id_fn = |message: &GossipsubMessage| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId::from(s.finish().to_string())
        };
        let gossipsub_config = libp2p::gossipsub::GossipsubConfigBuilder::default()
            .message_id_fn(message_id_fn)
            .build()
            .expect("valid gossipsub config");

        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(identity.clone()),
            gossipsub_config,
        )
        .expect("valid gossipsub params");

        Self {
            ping: Ping::new(PingConfig::new()),
            identify: Identify::new(
                IdentifyConfig::new(PROTOCOL_VERSION.to_string(), identity.public())
                    .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia,
            gossipsub,
        }
    }
}

#[derive(Debug)]
pub enum Event {
    Ping(PingEvent),
    Identify(Box<IdentifyEvent>),
    Kademlia(KademliaEvent),
    Gossipsub(GossipsubEvent),
}

impl From<PingEvent> for Event {
    fn from(event: PingEvent) -> Self {
        Event::Ping(event)
    }
}

impl From<IdentifyEvent> for Event {
    fn from(event: IdentifyEvent) -> Self {
        Event::Identify(Box::new(event))
    }
}

impl From<KademliaEvent> for Event {
    fn from(event: KademliaEvent) -> Self {
        Event::Kademlia(event)
    }
}

impl From<GossipsubEvent> for Event {
    fn from(event: GossipsubEvent) -> Self {
        Event::Gossipsub(event)
    }
}

fn string_to_key(input: &str) -> kad::record::Key {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    kad::record::Key::new(&result.as_slice())
}
