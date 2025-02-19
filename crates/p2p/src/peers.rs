use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use sha3::{Digest, Sha3_256};

use crate::secret::Secret;

#[derive(Debug, Clone)]
pub struct Peer {
    pub connectivity: Connectivity,
    pub direction: Direction,
    pub addr: Option<Multiaddr>,
    pub keyed_network_group: Option<KeyedNetworkGroup>,
    /// All peers send and receive periodic pings. This field holds the smallest
    /// ping time from all the pings sent and received from this peer.
    pub min_ping: Option<Duration>,
    pub evicted: bool,
    pub useful: bool,
    // TODO are we still able to maintain info about peers' sync heads?
    // sync_status: Option<p2p_proto_v0::sync::Status>,
    /// When this peer last gossiped a valid transaction
    pub last_valid_transaction_gossip: Option<Instant>,
    /// When this peer last gossiped a valid block
    pub last_valid_block_gossip: Option<Instant>,
}

impl Peer {
    pub fn is_connected(&self) -> bool {
        matches!(self.connectivity, Connectivity::Connected { .. })
    }

    pub fn is_inbound(&self) -> bool {
        matches!(self.direction, Direction::Inbound)
    }

    pub fn is_outbound(&self) -> bool {
        matches!(self.direction, Direction::Outbound)
    }

    pub fn is_relayed(&self) -> bool {
        self.addr
            .as_ref()
            .is_some_and(|addr| addr.iter().any(|p| p == Protocol::P2pCircuit))
    }

    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.addr.as_ref().and_then(|addr| {
            addr.iter().find_map(|p| match p {
                Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
                Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
                _ => None,
            })
        })
    }

    /// The connection time of the peer, if he is connected.
    pub fn connected_at(&self) -> Option<Instant> {
        match self.connectivity {
            Connectivity::Connected { connected_at, .. } => Some(connected_at),
            Connectivity::Disconnecting { connected_at, .. } => connected_at,
            Connectivity::Disconnected { connected_at, .. } => connected_at,
            Connectivity::Dialing => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Connectivity {
    Dialing,
    Connected {
        /// When the peer was connected.
        connected_at: Instant,
    },
    Disconnecting {
        /// When the peer was connected, if he was connected.
        connected_at: Option<Instant>,
    },
    Disconnected {
        /// When the peer was connected, if he was connected.
        connected_at: Option<Instant>,
        /// When the peer was disconnected.
        disconnected_at: Instant,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug)]
pub(crate) struct PeerSet {
    peers: HashMap<PeerId, Peer>,
    /// How long to keep disconnected peers in the set.
    retention_period: Duration,
}

impl PeerSet {
    pub fn new(retention_period: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            retention_period,
        }
    }

    /// Update a peer in the set.
    ///
    /// Panics if the peer is not in the set.
    pub fn update(&mut self, peer_id: PeerId, update: impl FnOnce(&mut Peer)) {
        self.upsert(peer_id, update, || panic!("peer not in set"));
    }

    /// Update a peer in the set, or insert a new one if it is not present.
    pub fn upsert(
        &mut self,
        peer_id: PeerId,
        update: impl FnOnce(&mut Peer),
        insert: impl FnOnce() -> Peer,
    ) {
        // Remove peers that have been disconnected for too long.
        self.peers.retain(|_, peer| match peer.connectivity {
            Connectivity::Disconnected {
                disconnected_at, ..
            } => disconnected_at.elapsed() < self.retention_period,
            _ => true,
        });
        self.peers
            .entry(peer_id)
            .and_modify(update)
            .or_insert_with(insert);
    }

    pub fn get(&self, peer_id: PeerId) -> Option<&Peer> {
        self.peers.get(&peer_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (PeerId, &Peer)> {
        self.peers.iter().filter_map(|(peer_id, peer)| {
            // Filter out peers that have been disconnected for too long.
            match peer.connectivity {
                Connectivity::Disconnected {
                    disconnected_at, ..
                } if disconnected_at.elapsed() >= self.retention_period => None,
                _ => Some((*peer_id, peer)),
            }
        })
    }
}

/// A network group that is keyed by a secret, calculated as SHA3(secret || 16
/// bit prefix for IPv4 or 32 bit prefix for IPv6 addresses).
///
/// For a given secret and IP address, the network group is deterministic, but
/// unpredictable by the attacker. The keyed network group is used to ensure
/// that our node is connected to a diverse set of IP addresses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyedNetworkGroup(pub [u8; 32]);

impl KeyedNetworkGroup {
    pub fn new(secret: &Secret, addr: IpAddr) -> Self {
        let mut hasher = Sha3_256::default();
        secret.hash_into(&mut hasher);
        match addr {
            IpAddr::V4(ip) => hasher.update(&ip.octets()[..2]),
            IpAddr::V6(ip) => hasher.update(&ip.octets()[..4]),
        }
        Self(hasher.finalize().into())
    }
}
