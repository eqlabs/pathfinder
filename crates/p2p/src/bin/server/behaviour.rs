use std::time::Duration;

use libp2p::kad::store::MemoryStore;
use libp2p::kad::{self};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{identify, identity, ping};
use p2p::kademlia_protocol_name;
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::ChainId;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event", event_process = false)]
pub struct Behaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub p2p_stream: p2p_stream::Behaviour<p2p::sync::codec::Transactions>,
}

impl Behaviour {
    pub fn new(pub_key: identity::PublicKey) -> Self {
        let kademlia_config = kad::Config::new(kademlia_protocol_name(ChainId::SEPOLIA_TESTNET));

        let kademlia = kad::Behaviour::with_config(
            pub_key.to_peer_id(),
            MemoryStore::new(pub_key.to_peer_id()),
            kademlia_config,
        );

        let p2p_stream = p2p_stream::Behaviour::new(
            p2p_stream::Config::default()
                .max_concurrent_streams(100)
                .request_timeout(Duration::from_secs(60 * 60)),
        );

        Self {
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(identify::PROTOCOL_NAME.to_string(), pub_key)
                    .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
            ),
            kademlia,
            p2p_stream,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum Event {
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Kademlia(kad::Event),
    TransactionsSync(p2p_stream::Event<TransactionsRequest, TransactionsResponse>),
}

impl From<ping::Event> for Event {
    fn from(event: ping::Event) -> Self {
        Event::Ping(event)
    }
}

impl From<identify::Event> for Event {
    fn from(event: identify::Event) -> Self {
        Event::Identify(Box::new(event))
    }
}

impl From<kad::Event> for Event {
    fn from(event: kad::Event) -> Self {
        Event::Kademlia(event)
    }
}

impl From<p2p_stream::Event<TransactionsRequest, TransactionsResponse>> for Event {
    fn from(event: p2p_stream::Event<TransactionsRequest, TransactionsResponse>) -> Self {
        Event::TransactionsSync(event)
    }
}
