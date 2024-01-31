use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use libp2p::PeerId;

#[derive(Debug, Clone)]
pub struct Peer {
    pub connectivity: Connectivity,
    pub direction: Direction,
    pub evicted: bool,
    pub useful: bool,
    pub relayed: bool,
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
}

#[derive(Debug, Clone, Copy)]
pub enum Connectivity {
    Dialing,
    Connected(Instant),
    Disconnected(Instant),
}

impl Connectivity {
    pub fn connected() -> Self {
        Self::Connected(Instant::now())
    }

    pub fn disconnected() -> Self {
        Self::Disconnected(Instant::now())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Direction {
    Inbound,
    Outbound,
}

#[derive(Debug, Default)]
pub struct PeerSet {
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
            Connectivity::Disconnected(when) => {
                Instant::now().duration_since(when) < self.retention_period
            }
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

    pub fn contains(&self, peer_id: PeerId) -> bool {
        self.peers.contains_key(&peer_id)
    }

    pub fn iter(&self) -> impl Iterator<Item = (PeerId, Peer)> + '_ {
        self.peers
            .iter()
            .map(|(peer_id, peer)| (*peer_id, peer.clone()))
    }
}
