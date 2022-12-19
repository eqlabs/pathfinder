use std::collections::HashMap;

use libp2p::PeerId;

#[derive(Debug, Default)]
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

    pub fn is_connected(&self) -> bool {
        matches!(self.connection_status, ConnectionStatus::Connected)
    }
}

#[derive(Debug, Default, Clone)]
enum ConnectionStatus {
    #[default]
    Disconnected,
    Dialing,
    Connected,
    Disconnecting,
}

#[derive(Debug, Default)]
pub struct Peers {
    peers: HashMap<PeerId, Peer>,
}

impl Peers {
    fn update_connection_status(&mut self, peer_id: &PeerId, connection_status: ConnectionStatus) {
        self.peers
            .entry(*peer_id)
            .or_insert_with(Default::default)
            .update_connection_status(connection_status);
    }

    pub fn update_sync_status(&mut self, peer_id: &PeerId, sync_status: p2p_proto::sync::Status) {
        self.peers
            .entry(*peer_id)
            .and_modify(|peer| peer.update_sync_status(sync_status));
    }

    pub fn peer_dialing(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Dialing)
    }

    pub fn peer_connected(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Connected)
    }

    pub fn peer_disconnecting(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Disconnecting)
    }

    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        self.update_connection_status(peer_id, ConnectionStatus::Disconnected)
    }

    pub fn peer_dial_error(&mut self, peer_id: &PeerId) {
        self.peers.entry(*peer_id).and_modify(|peer| {
            if !matches!(peer.connection_status(), ConnectionStatus::Connected) {
                // no successful connection yet, dialing failed, set to disconnected
                peer.update_connection_status(ConnectionStatus::Disconnected)
            };
        });
    }

    fn connection_status(&self, peer_id: &PeerId) -> Option<ConnectionStatus> {
        self.peers
            .get(peer_id)
            .map(|peer| peer.connection_status().clone())
    }

    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(ConnectionStatus::Connected)
        )
    }

    pub fn connected(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.iter().filter_map(|(peer_id, peer)| {
            if peer.is_connected() {
                Some(peer_id)
            } else {
                None
            }
        })
    }

    pub fn syncing(&self) -> impl Iterator<Item = (&PeerId, &p2p_proto::sync::Status)> {
        self.peers
            .iter()
            .filter_map(|(peer_id, peer)| peer.sync_status.as_ref().map(|status| (peer_id, status)))
    }

    pub fn remove(&mut self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }
}
