use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::Duration;

use crate::recent_peers::RecentPeers;
use crate::sync::codec;
use crate::Config;
use anyhow::anyhow;
use libp2p::core::Endpoint;
use libp2p::dcutr;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId};
use libp2p::identify;
use libp2p::identity;
use libp2p::kad::{self, store::MemoryStore};
use libp2p::multiaddr::Protocol;
use libp2p::ping;
use libp2p::relay;
use libp2p::swarm::{
    ConnectionClosed, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};
use libp2p::StreamProtocol;
use libp2p::{autonat, Multiaddr, PeerId};
use p2p_proto::block::{
    BlockBodiesRequest, BlockBodiesResponse, BlockHeadersRequest, BlockHeadersResponse,
};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::ChainId;
use std::task;

pub const IDENTIFY_PROTOCOL_NAME: &str = "/starknet/id/1.0.0";

pub fn kademlia_protocol_name(chain_id: ChainId) -> String {
    format!("/starknet/kad/{}/1.0.0", chain_id.to_hex_str())
}

pub struct Behaviour {
    cfg: Config,
    /// Recent peers that have connected to us directly (not over a relay).
    ///
    /// The distinction is important because different limits apply to direct and relayed peers.
    recent_inbound_direct_peers: RecentPeers,
    /// Recent peers that have connected to us over a relay.
    recent_inbound_relay_peers: RecentPeers,
    /// Number of peers that have inbound connections open to us directly (not over a relay).
    inbound_direct_peers: usize,
    /// Number of peers that have inbound connections open to us over a relay.
    inbound_relay_peers: usize,
    /// Peers connected to our node. Used for closing duplicate connections.
    connected_peers: HashSet<PeerId>,
    inner: Inner,
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "Event", event_process = false)]
pub struct Inner {
    relay: relay::client::Behaviour,
    autonat: autonat::Behaviour,
    dcutr: dcutr::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
    gossipsub: gossipsub::Behaviour,
    headers_sync: p2p_stream::Behaviour<codec::Headers>,
    bodies_sync: p2p_stream::Behaviour<codec::Bodies>,
    transactions_sync: p2p_stream::Behaviour<codec::Transactions>,
    receipts_sync: p2p_stream::Behaviour<codec::Receipts>,
    events_sync: p2p_stream::Behaviour<codec::Events>,
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = <Inner as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = <Inner as NetworkBehaviour>::ToSwarm;

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.on_established_connection(peer)?;

        // Is the peer connecting over a relay?
        let is_relay = remote_addr.iter().any(|p| p == Protocol::P2pCircuit);

        // Limit the number of inbound peer connections. Different limits apply to direct peers
        // and peers connecting over a relay.
        if is_relay {
            if self.inbound_relay_peers >= self.cfg.max_inbound_relay_peers {
                tracing::debug!(%connection_id, "Too many inbound relay peers, closing");
                return Err(ConnectionDenied::new(anyhow!(
                    "too many inbound relay peers"
                )));
            }
            self.inbound_relay_peers += 1;
        } else {
            if self.inbound_direct_peers >= self.cfg.max_inbound_direct_peers {
                tracing::debug!(%connection_id, "Too many inbound direct peers, closing");
                return Err(ConnectionDenied::new(anyhow!(
                    "too many inbound direct peers"
                )));
            }
            self.inbound_direct_peers += 1;
        }

        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.on_established_connection(peer)?;
        self.inner
            .handle_established_outbound_connection(connection_id, peer, addr, role_override)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        if let FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id, endpoint, ..
        }) = event
        {
            // Is this an inbound connection?
            if endpoint.is_listener() {
                if endpoint.is_relayed() {
                    self.inbound_relay_peers -= 1;
                } else {
                    self.inbound_direct_peers -= 1;
                }
            }
            self.connected_peers.remove(&peer_id);
        }
        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        self.inner.poll(cx)
    }

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        // Extract the IP address of the peer from his multiaddr.
        let peer_ip = remote_addr.iter().find_map(|p| match p {
            Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
            _ => None,
        });

        // If the peer has no IP address, disconnect.
        let Some(peer_ip) = peer_ip else {
            tracing::debug!(%connection_id, "Disconnected peer without IP");
            return Err(ConnectionDenied::new(anyhow!("peer without IP")));
        };

        // If the peer is not in the IP whitelist, disconnect.
        if !self
            .cfg
            .ip_whitelist
            .iter()
            .any(|net| net.contains(&peer_ip))
        {
            tracing::debug!(%peer_ip, %connection_id, "Disconnected peer not in IP whitelist");
            return Err(ConnectionDenied::new(anyhow!("peer not in IP whitelist")));
        }

        // Is the peer connecting over a relay?
        let is_relay = remote_addr.iter().any(|p| p == Protocol::P2pCircuit);

        // Prevent the peer from reconnecting too quickly.
        //
        // Different connection timeouts apply to direct peers and peers connecting over a relay.
        let recent_peers = if is_relay {
            &mut self.recent_inbound_relay_peers
        } else {
            &mut self.recent_inbound_direct_peers
        };

        // If the peer is in the recent peers set, this means he is attempting to
        // reconnect too quickly. Close the connection.
        if recent_peers.contains(&peer_ip) {
            tracing::debug!(%connection_id, "Peer attempted to reconnect too quickly, closing");
            return Err(ConnectionDenied::new(anyhow!("reconnect too quickly")));
        } else {
            // Otherwise, add the peer to the recent peers set.
            recent_peers.insert(peer_ip);
        }

        // Limit the number of inbound peer connections. Different limits apply to direct peers
        // and peers connecting over a relay.
        //
        // This same check happens when the connection is established, but we are also checking
        // here because it allows us to avoid potentially expensive protocol negotiation with the
        // peer if there are already too many inbound connections.
        //
        // The check must be repeated when the connection is established due to race conditions,
        // since multiple peers may be attempting to connect at the same time.
        if is_relay {
            if self.inbound_relay_peers >= self.cfg.max_inbound_relay_peers {
                tracing::debug!(%connection_id, "Too many inbound relay peers, closing");
                return Err(ConnectionDenied::new(anyhow!(
                    "too many inbound relay peers"
                )));
            }
        } else if self.inbound_direct_peers >= self.cfg.max_inbound_direct_peers {
            tracing::debug!(%connection_id, "Too many inbound direct peers, closing");
            return Err(ConnectionDenied::new(anyhow!(
                "too many inbound direct peers"
            )));
        }

        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }
}

impl Behaviour {
    pub fn new(
        identity: &identity::Keypair,
        chain_id: ChainId,
        cfg: Config,
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
                recent_inbound_direct_peers: RecentPeers::new(cfg.direct_connection_timeout),
                recent_inbound_relay_peers: RecentPeers::new(cfg.relay_connection_timeout),
                inbound_direct_peers: Default::default(),
                inbound_relay_peers: Default::default(),
                cfg,
                connected_peers: Default::default(),
                inner: Inner {
                    relay,
                    autonat: autonat::Behaviour::new(peer_id, Default::default()),
                    dcutr: dcutr::Behaviour::new(peer_id),
                    ping: ping::Behaviour::new(ping::Config::new()),
                    identify: identify::Behaviour::new(
                        identify::Config::new(
                            IDENTIFY_PROTOCOL_NAME.to_string(),
                            identity.public(),
                        )
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
            },
            relay_transport,
        )
    }

    pub fn provide_capability(&mut self, capability: &str) -> anyhow::Result<()> {
        let key = string_to_key(capability);
        self.inner.kademlia.start_providing(key)?;
        Ok(())
    }

    pub fn get_capability_providers(&mut self, capability: &str) -> kad::QueryId {
        let key = string_to_key(capability);
        self.inner.kademlia.get_providers(key)
    }

    pub fn subscribe_topic(&mut self, topic: &IdentTopic) -> anyhow::Result<()> {
        self.inner.gossipsub.subscribe(topic)?;
        Ok(())
    }

    fn on_established_connection(&mut self, peer_id: PeerId) -> Result<(), ConnectionDenied> {
        // Only allow one connection per peer.
        if self.connected_peers.contains(&peer_id) {
            tracing::debug!(%peer_id, "Peer already connected, closing");
            return Err(ConnectionDenied::new(anyhow!("duplicate connection")));
        }
        self.connected_peers.insert(peer_id);
        Ok(())
    }

    pub fn kademlia_mut(&mut self) -> &mut kad::Behaviour<MemoryStore> {
        &mut self.inner.kademlia
    }

    pub fn gossipsub_mut(&mut self) -> &mut gossipsub::Behaviour {
        &mut self.inner.gossipsub
    }

    pub fn headers_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Headers> {
        &mut self.inner.headers_sync
    }

    pub fn bodies_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Bodies> {
        &mut self.inner.bodies_sync
    }

    pub fn transactions_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Transactions> {
        &mut self.inner.transactions_sync
    }

    pub fn receipts_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Receipts> {
        &mut self.inner.receipts_sync
    }

    pub fn events_sync_mut(&mut self) -> &mut p2p_stream::Behaviour<codec::Events> {
        &mut self.inner.events_sync
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
