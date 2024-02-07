use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};

#[derive(Debug, Clone)]
pub struct Peer {
    pub connectivity: Connectivity,
    pub direction: Direction,
    pub addr: Option<Multiaddr>,
    pub evicted: bool,
    pub useful: bool,
    // TODO are we still able to maintain info about peers' sync heads?
    // sync_status: Option<p2p_proto_v0::sync::Status>,
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
            .map_or(false, |addr| addr.iter().any(|p| p == Protocol::P2pCircuit))
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
