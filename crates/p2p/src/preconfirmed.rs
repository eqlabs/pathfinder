//! Preconfirmed behaviour and other related utilities for the preconfirmed p2p
//! network.
use libp2p::PeerId;
#[cfg(test)]
use tokio::sync::mpsc::Sender;

mod behaviour;
mod client;

pub use behaviour::Behaviour;
pub use client::Client;
#[cfg(test)]
use libp2p::gossipsub::PublishError;

/// The topic for preconfirmed transactions in the network.
pub const TOPIC_PRECONFIRMED_TRANSACTIONS: &str = "preconfirmed_transactions";

/// Commands for the preconfirmed behaviour.
#[derive(Debug, Clone)]
pub enum Command {
    /// Test command to gossip some dummy preconfirmed transactions. This is
    /// necessary because by default Pathfinder is only supposed to be the
    /// recipient of gossiped preconfirmed transactions, and thus doesn't
    /// have a command in prod code to send them.
    #[cfg(test)]
    TestGossipPreconfirmedTransactions {
        done_tx: Sender<Result<(), PublishError>>,
    },
}

/// Events emitted by the preconfirmed behaviour.
#[derive(Debug, Clone)]
pub struct Event {
    pub source: PeerId,
    pub kind: EventKind,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq)]
pub enum EventKind {
    // TODO this is a placeholder
    /// A batch of preconfirmed transactions.
    PreconfirmedTransactionsPlaceholder,
    Subscribed,
}

// TODO this is a placeholder
/// The state of the preconfirmed P2P network.
#[derive(Default, Debug)]
pub struct State;

impl State {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use libp2p::identity;

    use super::*;
    use crate::test_utils::peer::{TestPeer, TestPeerBuilder};

    type PcTestPeer = TestPeer<Behaviour>;

    fn create_peer() -> PcTestPeer {
        TestPeerBuilder::new()
            .app_behaviour(Behaviour::new(identity::Keypair::generate_ed25519()))
            .build(crate::core::Config::for_test())
    }

    async fn create_peers() -> (PcTestPeer, PcTestPeer) {
        let mut server = create_peer();
        let client = create_peer();

        let server_addr = server.start_listening().await.unwrap();

        tracing::info!(%server.peer_id, %server_addr, "Server");
        tracing::info!(%client.peer_id, "Client");

        client
            .client
            .dial(server.peer_id, server_addr)
            .await
            .unwrap();

        (server, client)
    }

    async fn wait_for_subscribed(peer: &mut PcTestPeer, expected_peer_id: PeerId) {
        peer.wait_for_event(|e| {
            (matches!(e.kind, EventKind::Subscribed) && expected_peer_id == e.source).then_some(())
        })
        .await
        .unwrap();
    }

    /// A simple sanity test to check gossiping between two nodes.
    #[tokio::test]
    async fn sanity() {
        let (mut server, mut client) = create_peers().await;
        wait_for_subscribed(&mut client, server.peer_id).await;
        wait_for_subscribed(&mut server, client.peer_id).await;

        let (done_tx, mut done_rx) = tokio::sync::mpsc::channel(1);

        client
            .client
            .send(Command::TestGossipPreconfirmedTransactions { done_tx })
            .await
            .unwrap();
        // Wait for the gossip to complete
        done_rx.recv().await.unwrap().unwrap();

        server
            .wait_for_event(|e| {
                matches!(e.kind, EventKind::PreconfirmedTransactionsPlaceholder).then_some(())
            })
            .await
            .unwrap();
    }
}
