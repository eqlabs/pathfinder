use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use libp2p::PeerId;

/// Set of recently connected peers. Peers are tracked primarily by their IP address, but the
/// peer ID is also stored to allow for removal of peers.
///
/// Peers are removed from the set after a timeout. The actual removal only happens once any
/// of the methods on this type are called.
#[derive(Debug)]
pub struct RecentPeers {
    instants: HashMap<IpAddr, Instant>,
    ips: HashMap<PeerId, IpAddr>,
    timeout: Duration,
}

impl RecentPeers {
    pub fn new(timeout: Duration) -> Self {
        Self {
            instants: HashMap::new(),
            ips: HashMap::new(),
            timeout,
        }
    }

    /// Insert the peer into the recent peers set.
    ///
    /// Panics if the peer is already in the set.
    pub fn insert(&mut self, peer_id: PeerId, peer_ip: IpAddr) {
        if self.instants.insert(peer_ip, Instant::now()).is_some() {
            panic!("peer already in the set, was insert called before contains?");
        }
        self.ips.insert(peer_id, peer_ip);
    }

    /// Returns `true` if the peer with the given IP is in the recent peers set.
    ///
    /// Removes the peer from the set if it is expired.
    pub fn contains(&mut self, peer_ip: &IpAddr) -> bool {
        match self.instants.get(peer_ip) {
            Some(instant) if instant.elapsed() < self.timeout => true,
            _ => {
                self.instants.remove(peer_ip);
                false
            }
        }
    }

    /// Removes the peer from the set if it is expired.
    pub fn remove_if_expired(&mut self, peer_id: PeerId) {
        if let Some(&ip) = self.ips.get(&peer_id) {
            // The contains method removes the peer IP if it is expired.
            if !self.contains(&ip) {
                // The peer IP is removed from the set, so we need to remove the
                // peer ID mapping as well.
                self.ips.remove(&peer_id);
            }
        }
    }
}
