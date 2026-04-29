//! Preconfirmed behaviour and other related utilities for the preconfirmed p2p
//! network.
use libp2p::gossipsub::TopicHash;
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
}

#[derive(Debug, Clone)]
pub struct TestEvent {
    pub source: PeerId,
    pub kind: TestEventKind,
}

#[derive(Debug, Clone)]
pub enum TestEventKind {
    Subscribed(TopicHash),
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
    use libp2p::gossipsub::Sha256Topic;
    use libp2p::identity;

    use super::*;
    use crate::test_utils::peer::{create_and_connect_pair, TestPeer, TestPeerBuilder};

    type PcTestPeer = TestPeer<Behaviour>;

    fn create_peer() -> PcTestPeer {
        TestPeerBuilder::new()
            .app_behaviour(Behaviour::new(identity::Keypair::generate_ed25519()))
            .build(crate::core::Config::for_test())
    }

    async fn create_peers() -> (PcTestPeer, PcTestPeer) {
        create_and_connect_pair(create_peer).await
    }

    async fn wait_for_subscribed(peer: &mut PcTestPeer, expected_peer_id: PeerId) {
        let topic_hash = Sha256Topic::new(TOPIC_PRECONFIRMED_TRANSACTIONS).hash();
        peer.wait_for_app_test_event(|e| {
            let TestEventKind::Subscribed(t) = e.kind;
            (t == topic_hash && e.source == expected_peer_id).then_some(())
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
