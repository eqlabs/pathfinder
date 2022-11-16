use std::{collections::HashMap, sync::Arc};

use libp2p::{Multiaddr, PeerId};
use tokio::sync::RwLock;

#[derive(Default)]
struct Peer {
    pub listening_addresses: Vec<Multiaddr>,
}

#[derive(Default, Clone)]
pub struct Peers {
    inner: Arc<RwLock<HashMap<PeerId, Peer>>>,
}

impl Peers {
    pub async fn add(&mut self, peer_id: PeerId, listening_addresses: Vec<Multiaddr>) {
        self.inner.write().await.insert(
            peer_id,
            Peer {
                listening_addresses,
            },
        );
    }

    pub async fn remove(&mut self, peer_id: &PeerId) {
        self.inner.write().await.remove(peer_id);
    }

    // TODO: temporary accessor to get a peer id
    pub async fn first(&self) -> Option<PeerId> {
        self.inner.read().await.keys().cloned().next()
    }
}
