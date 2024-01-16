use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use crate::sync::codec;
use libp2p::autonat;
use libp2p::dcutr;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId};
use libp2p::identify;
use libp2p::identity;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::ping;
use libp2p::relay;
use libp2p::swarm::NetworkBehaviour;
use libp2p::StreamProtocol;
use p2p_proto::block::{
    BlockBodiesRequest, BlockBodiesResponse, BlockHeadersRequest, BlockHeadersResponse,
};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::ChainId;

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event", event_process = false)]
pub struct Behaviour {
    relay: relay::client::Behaviour,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub headers_sync: p2p_stream::Behaviour<codec::Headers>,
    pub bodies_sync: p2p_stream::Behaviour<codec::Bodies>,
    pub transactions_sync: p2p_stream::Behaviour<codec::Transactions>,
    pub receipts_sync: p2p_stream::Behaviour<codec::Receipts>,
    pub events_sync: p2p_stream::Behaviour<codec::Events>,
}

pub const IDENTIFY_PROTOCOL_NAME: &str = "/starknet/id/1.0.0";

pub fn kademlia_protocol_name(chain_id: ChainId) -> String {
    format!("/starknet/kad/{}/1.0.0", chain_id.to_hex_str())
}

impl Behaviour {
    pub fn new(
        identity: &identity::Keypair,
        chain_id: ChainId,
    ) -> (Self, relay::client::Transport) {
        const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(600);

        let mut kademlia_config = kad::Config::default();
        kademlia_config.set_record_ttl(Some(Duration::from_secs(0)));
        kademlia_config.set_provider_record_ttl(Some(PROVIDER_PUBLICATION_INTERVAL * 3));
        kademlia_config.set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));
        // This makes sure that the DHT we're implementing is incompatible with the "default" IPFS
        // DHT from libp2p.
        kademlia_config.set_protocol_names(vec![StreamProtocol::try_from_owned(
            kademlia_protocol_name(chain_id),
        )
        .unwrap()]);

        let peer_id = identity.public().to_peer_id();

        let kademlia =
            kad::Behaviour::with_config(peer_id, MemoryStore::new(peer_id), kademlia_config);

        // FIXME: find out how we should derive message id
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            MessageId::from(s.finish().to_string())
        };
        let gossipsub_config = libp2p::gossipsub::ConfigBuilder::default()
            .message_id_fn(message_id_fn)
            .build()
            .expect("valid gossipsub config");

        let gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(identity.clone()),
            gossipsub_config,
        )
        .expect("valid gossipsub params");

        let headers_sync = request_response_behavior::<codec::Headers>();
        let bodies_sync = request_response_behavior::<codec::Bodies>();
        let transactions_sync = request_response_behavior::<codec::Transactions>();
        let receipts_sync = request_response_behavior::<codec::Receipts>();
        let events_sync = request_response_behavior::<codec::Events>();

        let (relay_transport, relay) = relay::client::new(peer_id);

        (
            Self {
                relay,
                autonat: autonat::Behaviour::new(peer_id, Default::default()),
                dcutr: dcutr::Behaviour::new(peer_id),
                ping: ping::Behaviour::new(ping::Config::new()),
                identify: identify::Behaviour::new(
                    identify::Config::new(IDENTIFY_PROTOCOL_NAME.to_string(), identity.public())
                        .with_agent_version(format!("pathfinder/{}", env!("CARGO_PKG_VERSION"))),
                ),
                kademlia,
                gossipsub,
                headers_sync,
                bodies_sync,
                transactions_sync,
                receipts_sync,
                events_sync,
            },
            relay_transport,
        )
    }

    pub fn provide_capability(&mut self, capability: &str) -> anyhow::Result<()> {
        let key = string_to_key(capability);
        self.kademlia.start_providing(key)?;
        Ok(())
    }

    pub fn get_capability_providers(&mut self, capability: &str) -> kad::QueryId {
        let key = string_to_key(capability);
        self.kademlia.get_providers(key)
    }

    pub fn subscribe_topic(&mut self, topic: &IdentTopic) -> anyhow::Result<()> {
        self.gossipsub.subscribe(topic)?;
        Ok(())
    }
}

fn request_response_behavior<C>() -> p2p_stream::Behaviour<C>
where
    C: Default + p2p_stream::Codec + Clone + Send,
    C::Protocol: Default,
{
    p2p_stream::Behaviour::new(std::iter::once(C::Protocol::default()), Default::default())
}

#[derive(Debug)]
pub enum Event {
    Relay(relay::client::Event),
    Autonat(autonat::Event),
    Dcutr(dcutr::Event),
    Ping(ping::Event),
    Identify(Box<identify::Event>),
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
    HeadersSync(p2p_stream::Event<BlockHeadersRequest, BlockHeadersResponse>),
    BodiesSync(p2p_stream::Event<BlockBodiesRequest, BlockBodiesResponse>),
    TransactionsSync(p2p_stream::Event<TransactionsRequest, TransactionsResponse>),
    ReceiptsSync(p2p_stream::Event<ReceiptsRequest, ReceiptsResponse>),
    EventsSync(p2p_stream::Event<EventsRequest, EventsResponse>),
}

impl From<relay::client::Event> for Event {
    fn from(event: relay::client::Event) -> Self {
        Event::Relay(event)
    }
}

impl From<autonat::Event> for Event {
    fn from(event: autonat::Event) -> Self {
        Event::Autonat(event)
    }
}

impl From<dcutr::Event> for Event {
    fn from(event: dcutr::Event) -> Self {
        Event::Dcutr(event)
    }
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

impl From<gossipsub::Event> for Event {
    fn from(event: gossipsub::Event) -> Self {
        Event::Gossipsub(event)
    }
}

impl From<p2p_stream::Event<BlockHeadersRequest, BlockHeadersResponse>> for Event {
    fn from(event: p2p_stream::Event<BlockHeadersRequest, BlockHeadersResponse>) -> Self {
        Event::HeadersSync(event)
    }
}

impl From<p2p_stream::Event<BlockBodiesRequest, BlockBodiesResponse>> for Event {
    fn from(event: p2p_stream::Event<BlockBodiesRequest, BlockBodiesResponse>) -> Self {
        Event::BodiesSync(event)
    }
}

impl From<p2p_stream::Event<TransactionsRequest, TransactionsResponse>> for Event {
    fn from(event: p2p_stream::Event<TransactionsRequest, TransactionsResponse>) -> Self {
        Event::TransactionsSync(event)
    }
}

impl From<p2p_stream::Event<ReceiptsRequest, ReceiptsResponse>> for Event {
    fn from(event: p2p_stream::Event<ReceiptsRequest, ReceiptsResponse>) -> Self {
        Event::ReceiptsSync(event)
    }
}

impl From<p2p_stream::Event<EventsRequest, EventsResponse>> for Event {
    fn from(event: p2p_stream::Event<EventsRequest, EventsResponse>) -> Self {
        Event::EventsSync(event)
    }
}

fn string_to_key(input: &str) -> kad::RecordKey {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    kad::RecordKey::new(&result.as_slice())
}
