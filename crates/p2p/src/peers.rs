use std::{collections::HashMap, sync::Arc};

use libp2p::PeerId;
use tokio::sync::RwLock;

#[derive(Default)]
struct Peer {
    connection_status: ConnectionStatus,
    sync_status: Option<p2p_proto::sync::Status>,
}

impl Peer {
    pub fn connection_status(&self) -> &ConnectionStatus {
        &self.connection_status
    }

    pub fn update_connection_status(&mut self, new_status: ConnectionStatus) {
        use ConnectionStatus::*;

        self.connection_status = match (&self.connection_status, new_status) {
            (Connected, Dialing) => Connected,
            (_, new_status) => new_status,
        };
    }

    pub fn update_sync_status(&mut self, new_status: p2p_proto::sync::Status) {
        self.sync_status = Some(new_status);
    }
}

#[derive(Default, Clone)]
enum ConnectionStatus {
    #[default]
    Disconnected,
    Dialing,
    Connected,
    Disconnecting,
}

#[derive(Default, Clone)]
pub struct Peers {
    inner: Arc<RwLock<HashMap<PeerId, Peer>>>,
}

impl Peers {
    async fn update_connection_status(
        &mut self,
        peer_id: &PeerId,
        connection_status: ConnectionStatus,
    ) {
        self.inner
            .write()
            .await
            .entry(*peer_id)
            .or_insert_with(|| Default::default())
            .update_connection_status(connection_status);
    }

    pub async fn update_sync_status(
        &mut self,
        peer_id: &PeerId,
        sync_status: p2p_proto::sync::Status,
    ) {
        self.inner
            .write()
            .await
            .entry(*peer_id)
            .and_modify(|peer| peer.update_sync_status(sync_status));
    }

    pub async fn peer_dialing(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Dialing)
            .await;
    }

    pub async fn peer_connected(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Connected)
            .await;
    }

    pub async fn peer_disconnecting(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Disconnecting)
            .await;
    }

    pub async fn peer_disconnected(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Disconnected)
            .await;
    }

    pub async fn peer_dial_error(&mut self, peer_id: &PeerId) {
        self.inner.write().await.entry(*peer_id).and_modify(|peer| {
            if !matches!(peer.connection_status(), ConnectionStatus::Connected) {
                // no successful connection yet, dialing failed, set to disconnected
                peer.update_connection_status(ConnectionStatus::Disconnected)
            };
        });
    }

    async fn connection_status(&self, peer_id: &PeerId) -> Option<ConnectionStatus> {
        self.inner
            .read()
            .await
            .get(peer_id)
            .map(|peer| peer.connection_status().clone())
    }

    pub async fn is_connected(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id).await,
            Some(ConnectionStatus::Connected)
        )
    }

    pub async fn remove(&mut self, peer_id: &PeerId) {
        self.inner.write().await.remove(peer_id);
    }
}
