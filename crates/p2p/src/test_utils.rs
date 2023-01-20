use super::{behaviour, Command, Event, TestCommand, TestEvent};
use libp2p::{
    gossipsub::GossipsubEvent,
    kad::{QueryId, QueryResult},
    swarm::SwarmEvent,
    PeerId,
};
use std::collections::{HashMap, HashSet};
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub(super) struct Client {
    sender: mpsc::Sender<Command>,
}

impl Client {
    pub(super) fn new(sender: mpsc::Sender<Command>) -> Self {
        Self { sender }
    }
}

impl Client {
    pub async fn get_peers_from_dht(&self) -> HashSet<PeerId> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Command::_Test(TestCommand::GetPeersFromDHT(sender)))
            .await
            .expect("Command receiver not to be dropped");
        receiver.await.expect("Sender not to be dropped")
    }

    pub async fn get_providers(&self, key: Vec<u8>) -> Result<HashSet<PeerId>, ()> {
        let (sender, mut receiver) = mpsc::channel(1);
        self.sender
            .send(Command::_Test(TestCommand::GetProviders { key, sender }))
            .await
            .expect("Command receiver not to be dropped");

        let mut providers = HashSet::new();

        while let Some(partial_result) = receiver.recv().await {
            match partial_result {
                Ok(more_providers) => providers.extend(more_providers.into_iter()),
                Err(_) => return Err(()),
            }
        }

        Ok(providers)
    }
}

pub(super) async fn handle_event<E: std::fmt::Debug>(
    event_sender: &mpsc::Sender<Event>,
    event: SwarmEvent<behaviour::Event, E>,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            send_event(event_sender, TestEvent::NewListenAddress(address)).await;
        }
        SwarmEvent::Behaviour(behaviour::Event::Gossipsub(GossipsubEvent::Subscribed {
            peer_id,
            topic,
        })) => {
            send_event(
                event_sender,
                TestEvent::Subscribed {
                    remote: peer_id,
                    topic: topic.into_string(),
                },
            )
            .await;
        }
        _ => {}
    }
}

pub(super) async fn handle_command(
    behavior: &mut behaviour::Behaviour,
    command: TestCommand,
    pending_test_queries: &mut PendingQueries,
) {
    match command {
        TestCommand::GetPeersFromDHT(sender) => {
            let peers = behavior
                .kademlia
                .kbuckets()
                // Cannot .into_iter() a KBucketRef, hence the inner collect followed by flat_map
                .map(|kbucket_ref| {
                    kbucket_ref
                        .iter()
                        .map(|entry_ref| *entry_ref.node.key.preimage())
                        .collect::<Vec<_>>()
                })
                .flat_map(|peers_in_bucket| peers_in_bucket.into_iter())
                .collect::<HashSet<_>>();
            sender.send(peers).expect("Receiver not to be dropped")
        }
        TestCommand::GetProviders { key, sender } => {
            let query_id = behavior.kademlia.get_providers(key.into());
            pending_test_queries.get_providers.insert(query_id, sender);
        }
    }
}

pub(super) async fn send_event(event_sender: &mpsc::Sender<Event>, event: TestEvent) {
    event_sender
        .send(Event::Test(event))
        .await
        .expect("Event receiver not to be dropped");
}

pub(super) async fn query_completed(
    pending_test_queries: &mut PendingQueries,
    event_sender: &mpsc::Sender<Event>,
    id: QueryId,
    result: QueryResult,
) {
    match result {
        QueryResult::GetProviders(result) => {
            use libp2p::kad::GetProvidersOk;

            let result = match result {
                Ok(GetProvidersOk::FoundProviders { providers, .. }) => Ok(providers),
                Ok(GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => Ok(Default::default()),
                Err(_) => Err(()),
            };

            let sender = pending_test_queries
                .get_providers
                .remove(&id)
                .expect("Query to be pending");

            sender
                .send(result)
                .await
                .expect("Receiver not to be dropped");
        }
        QueryResult::StartProviding(result) => {
            use libp2p::kad::AddProviderOk;

            let result = match result {
                Ok(AddProviderOk { key }) => Ok(key),
                Err(error) => Err(error.into_key()),
            };
            send_event(event_sender, TestEvent::StartProvidingCompleted(result)).await
        }
        _ => {}
    }
}

pub(super) async fn query_progressed(
    pending_test_queries: &PendingQueries,
    id: QueryId,
    result: QueryResult,
) {
    if let QueryResult::GetProviders(result) = result {
        use libp2p::kad::GetProvidersOk;

        let result = match result {
            Ok(GetProvidersOk::FoundProviders { providers, .. }) => Ok(providers),
            Ok(_) => Ok(Default::default()),
            Err(_) => {
                unreachable!("when a query times out libp2p makes it the last stage")
            }
        };

        let sender = pending_test_queries
            .get_providers
            .get(&id)
            .expect("Query to be pending");

        sender
            .send(result)
            .await
            .expect("Receiver not to be dropped");
    }
}

#[derive(Debug, Default)]
pub(super) struct PendingQueries {
    pub get_providers: HashMap<QueryId, mpsc::Sender<Result<HashSet<PeerId>, ()>>>,
}
