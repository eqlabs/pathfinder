use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

/// Set of recently connected peers tracked by their IP address.
///
/// Peers are removed from the set after a timeout. The actual removal only happens once one
/// of the methods on this type is called.
#[derive(Debug)]
pub struct RecentPeers {
    peers: HashMap<IpAddr, Instant>,
    timeout: Duration,
}

impl RecentPeers {
    pub fn new(timeout: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            timeout,
        }
    }

    /// Insert the peer into the recent peers set.
    ///
    /// Removes all expired peers. Panics if the peer is already in the set.
    pub fn insert(&mut self, peer_ip: IpAddr) {
        self.peers
            .retain(|_, instant| instant.elapsed() < self.timeout);
        if self.peers.insert(peer_ip, Instant::now()).is_some() {
            panic!("peer already in the set, was insert called before contains?");
        }
    }

    /// Returns `true` if the peer with the given IP is in the recent peers set.
    ///
    /// Removes the peer from the set if it is expired.
    pub fn contains(&mut self, peer_ip: &IpAddr) -> bool {
        match self.peers.get(peer_ip) {
            Some(instant) if instant.elapsed() < self.timeout => true,
            _ => {
                self.peers.remove(peer_ip);
                false
            }
        }
    }
}
