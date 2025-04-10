use std::collections::HashSet;

use libp2p::kad::{QueryId, QueryResult};
use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use tokio::sync::mpsc;

use crate::core::{Behaviour, Event, TestCommand, TestEvent};

pub async fn handle_event<B: NetworkBehaviour>(
    event_sender: &mpsc::Sender<TestEvent>,
    event: SwarmEvent<Event<B>>,
) {
    if let SwarmEvent::NewListenAddr { address, .. } = event {
        send_event(event_sender, TestEvent::NewListenAddress(address)).await;
    }
}

pub async fn handle_command<B: NetworkBehaviour>(
    behavior: &mut Behaviour<B>,
    command: TestCommand,
    _pending_test_queries: &mut PendingQueries,
) {
    match command {
        TestCommand::GetPeersFromDHT(sender) => {
            if let Some(kad) = behavior.kademlia_mut() {
                let peers = kad
                    .kbuckets()
                    // Cannot .into_iter() a KBucketRef, hence the inner collect followed by
                    // flat_map
                    .map(|kbucket_ref| {
                        kbucket_ref
                            .iter()
                            .map(|entry_ref| *entry_ref.node.key.preimage())
                            .collect::<Vec<_>>()
                    })
                    .flat_map(|peers_in_bucket| peers_in_bucket.into_iter())
                    .collect::<HashSet<_>>();
                sender.send(peers).expect("Receiver not to be dropped");
            } else {
                tracing::warn!(
                    "Cannot handle `TestCommand::GetPeersFromDHT` because Kademlia is disabled"
                );
            }
        }
        TestCommand::GetConnectedPeers(sender) => {
            let peers = behavior
                .peers()
                .filter_map(|(peer_id, peer)| {
                    if peer.is_connected() {
                        Some((peer_id, peer.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            sender.send(peers).expect("Receiver not to be dropped")
        }
    }
}

pub async fn send_event(event_sender: &mpsc::Sender<TestEvent>, event: TestEvent) {
    event_sender
        .send(event)
        .await
        .expect("Event receiver not to be dropped");
}

pub async fn query_completed(
    _pending_test_queries: &mut PendingQueries,
    _event_sender: &mpsc::Sender<TestEvent>,
    _id: QueryId,
    _result: QueryResult,
) {
    // This fn as a placeholder for future query types in tests.
}

pub async fn query_progressed(
    _pending_test_queries: &PendingQueries,
    _id: QueryId,
    _result: QueryResult,
) {
    // This fn as a placeholder for future query types in tests.
}

#[derive(Debug, Default)]
pub struct PendingQueries {
    // QueryResult::GetProviders used to be handled here, but now just keeping this struct
    // as a placeholder for future query types in tests.
}
