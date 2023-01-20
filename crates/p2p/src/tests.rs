use crate::{
    self as p2p, BootstrapConfig, Event, EventReceiver, Peers, PeriodicTaskConfig, TestEvent,
};
use anyhow::{Context, Result};
use core::panic;
use libp2p::identity::{ed25519, Keypair};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

#[allow(dead_code)]
#[derive(Debug)]
struct TestPeer {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub peers: Arc<RwLock<Peers>>,
    pub client: p2p::Client,
    pub event_receiver: p2p::EventReceiver,
    pub main_loop_jh: JoinHandle<()>,
}

impl TestPeer {
    #[must_use]
    pub fn new(periodic_cfg: PeriodicTaskConfig) -> Self {
        let keypair = Keypair::Ed25519(ed25519::Keypair::generate());
        let peer_id = keypair.public().to_peer_id();
        let peers: Arc<RwLock<Peers>> = Default::default();
        let (client, event_receiver, main_loop) =
            p2p::new(keypair.clone(), peers.clone(), periodic_cfg);
        let main_loop_jh = tokio::spawn(main_loop.run());
        Self {
            keypair,
            peer_id,
            peers,
            client,
            event_receiver,
            main_loop_jh,
        }
    }

    /// Start listening on a specified address
    pub async fn start_listening_on(&mut self, addr: Multiaddr) -> Result<Multiaddr> {
        self.client
            .start_listening(addr)
            .await
            .context("Start listening failed")?;

        let event = tokio::time::timeout(Duration::from_secs(1), self.event_receiver.recv())
            .await
            .context("Timedout while waiting for new listen address")?
            .context("Event channel closed")?;

        let addr = match event {
            Event::Test(TestEvent::NewListenAddress(addr)) => addr,
            _ => anyhow::bail!("Unexpected event: {event:?}"),
        };
        Ok(addr)
    }

    /// Start listening on localhost with port automatically assigned
    pub async fn start_listening(&mut self) -> Result<Multiaddr> {
        self.start_listening_on(Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap())
            .await
    }

    /// Get peer IDs of the connected peers
    pub async fn connected(&self) -> HashSet<PeerId> {
        self.peers
            .read()
            .await
            .connected()
            .map(Clone::clone)
            .collect()
    }
}

impl Default for TestPeer {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

/// [`MainLoop`](p2p::MainLoop)'s event channel size is 1, so we need to consume
/// all events as soon as they're sent otherwise the main loop will stall.
/// `f` should return `Some(data)` where `data` is extracted from
/// the event type of interest. For other events that should be ignored
/// `f` should return `None`. This function returns a receiver to the filtered
/// events' data channel.
fn filter_events<T: Debug + Send + 'static>(
    mut event_receiver: EventReceiver,
    f: impl FnOnce(Event) -> Option<T> + Copy + Send + 'static,
) -> tokio::sync::mpsc::Receiver<T> {
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = event_receiver.recv() => if let Some(event) = event {
                    if let Some(data) = f(event) {
                        tx.send(data).await.unwrap()
                    }
                }
            }
        }
    });

    rx
}

/// [`MainLoop`](p2p::MainLoop)'s event channel size is 1, so we need to consume
/// all events as soon as they're sent otherwise the main loop will stall
fn consume_events(mut event_receiver: EventReceiver) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = event_receiver.recv() => {}
            }
        }
    });
}

#[test_log::test(tokio::test)]
async fn dial() {
    let _ = env_logger::builder().is_test(true).try_init();
    // tokio::time::pause() does not make a difference
    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr1 = peer1.start_listening().await.unwrap();
    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer1.peer_id, %addr1);
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    let peers_of1 = peer1.connected().await;
    let peers_of2 = peer2.connected().await;

    assert_eq!(peers_of1, [peer2.peer_id].into());
    assert_eq!(peers_of2, [peer1.peer_id].into());
}

#[test_log::test(tokio::test)]
async fn periodic_bootstrap() {
    let _ = env_logger::builder().is_test(true).try_init();

    // TODO figure out how to make this test run using tokio::time::pause()
    // instead of arbitrary short delays
    let periodic_cfg = PeriodicTaskConfig {
        bootstrap: BootstrapConfig {
            period: Duration::from_millis(500),
            start_offset: Duration::from_secs(1),
        },
        status_period: Duration::from_secs(60 * 60),
    };
    let mut boot = TestPeer::new(periodic_cfg);
    let mut peer1 = TestPeer::new(periodic_cfg);
    let mut peer2 = TestPeer::new(periodic_cfg);

    let mut boot_addr = boot.start_listening().await.unwrap();
    boot_addr.push(Protocol::P2p(boot.peer_id.into()));

    let addr1 = peer1.start_listening().await.unwrap();
    let addr2 = peer2.start_listening().await.unwrap();

    tracing::info!(%boot.peer_id, %boot_addr);
    tracing::info!(%peer1.peer_id, %addr1);
    tracing::info!(%peer2.peer_id, %addr2);

    peer1
        .client
        .dial(boot.peer_id, boot_addr.clone())
        .await
        .unwrap();
    peer2.client.dial(boot.peer_id, boot_addr).await.unwrap();

    let filter_periodic_bootstrap = |event| match event {
        Event::Test(TestEvent::PeriodicBootstrapCompleted(_)) => Some(()),
        _ => None,
    };

    consume_events(boot.event_receiver);

    let peer_id2 = peer2.peer_id;

    let mut peer2_added_to_dht_of_peer1 =
        filter_events(peer1.event_receiver, move |event| match event {
            Event::Test(TestEvent::PeerAddedToDHT { remote }) if remote == peer_id2 => Some(()),
            _ => None,
        });
    let mut peer2_bootstrap_done = filter_events(peer2.event_receiver, filter_periodic_bootstrap);

    tokio::join!(peer2_added_to_dht_of_peer1.recv(), async {
        peer2_bootstrap_done.recv().await;
        peer2_bootstrap_done.recv().await;
    });

    let boot_dht = boot.client.for_test().get_peers_from_dht().await;
    let dht1 = peer1.client.for_test().get_peers_from_dht().await;
    let dht2 = peer2.client.for_test().get_peers_from_dht().await;

    assert_eq!(boot_dht, [peer1.peer_id, peer2.peer_id].into());
    assert_eq!(dht1, [boot.peer_id, peer2.peer_id].into());
    assert_eq!(dht2, [boot.peer_id, peer1.peer_id].into());
}

#[test_log::test(tokio::test)]
async fn provide_capability() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr1 = peer1.start_listening().await.unwrap();
    let addr2 = peer2.start_listening().await.unwrap();

    tracing::info!(%peer1.peer_id, %addr1);
    tracing::info!(%peer2.peer_id, %addr2);

    let mut peer1_started_providing = filter_events(peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::StartProvidingCompleted(_)) => Some(()),
        _ => None,
    });
    consume_events(peer2.event_receiver);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();
    peer1.client.provide_capability("blah").await.unwrap();
    peer1_started_providing.recv().await;

    // Apparently sometimes still not yet providing at this point and there's
    // no other event to rely on
    tokio::time::sleep(Duration::from_millis(500)).await;

    // sha256("blah")
    let key =
        hex::decode("8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52").unwrap();
    let providers = peer2.client.for_test().get_providers(key).await.unwrap();

    assert_eq!(providers, [peer1.peer_id].into());
}

#[test_log::test(tokio::test)]
async fn subscription_and_propagation() {
    use fake::{Fake, Faker};
    use p2p_proto::propagation::{Message, NewBlockBody, NewBlockHeader, NewBlockState};

    let _ = env_logger::builder().is_test(true).try_init();

    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr1 = peer1.start_listening().await.unwrap();
    let addr2 = peer2.start_listening().await.unwrap();

    tracing::info!(%peer1.peer_id, %addr1);
    tracing::info!(%peer2.peer_id, %addr2);

    let mut peer2_subscribed_to_peer1 = filter_events(peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::Subscribed { .. }) => Some(()),
        _ => None,
    });

    let mut propagated_to_peer2 = filter_events(peer2.event_receiver, |event| match event {
        Event::BlockPropagation(message) => Some(message),
        _ => None,
    });

    const TOPIC: &str = "TOPIC";

    peer2.client.dial(peer1.peer_id, addr1).await.unwrap();
    peer2.client.subscribe_topic(TOPIC).await.unwrap();
    peer2_subscribed_to_peer1.recv().await;

    let new_block_header = Message::NewBlockHeader(Faker.fake::<NewBlockHeader>());
    let new_block_body = Message::NewBlockBody(Faker.fake::<NewBlockBody>());
    let new_block_state = Message::NewBlockState(Faker.fake::<NewBlockState>());

    for expected in [new_block_header, new_block_body, new_block_state] {
        peer1
            .client
            .publish_propagation_message(TOPIC, expected.clone())
            .await
            .unwrap();

        let msg = propagated_to_peer2.recv().await.unwrap();

        assert_eq!(msg, expected);
    }
}

#[test_log::test(tokio::test)]
async fn sync_request_response() {
    use fake::{Fake, Faker};
    use p2p_proto::sync::{
        BlockBodies, BlockHeaders, GetBlockBodies, GetBlockHeaders, GetStateDiffs, Request,
        Response, StateDiffs, Status,
    };

    let _ = env_logger::builder().is_test(true).try_init();

    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr1 = peer1.start_listening().await.unwrap();
    let addr2 = peer2.start_listening().await.unwrap();

    tracing::info!(%peer1.peer_id, %addr1);
    tracing::info!(%peer2.peer_id, %addr2);

    let mut peer1_inbound_sync_requests =
        filter_events(peer1.event_receiver, move |event| match event {
            Event::InboundSyncRequest {
                from,
                request,
                channel,
            } => {
                assert_eq!(from, peer2.peer_id);
                Some((request, channel))
            }
            _ => None,
        });

    consume_events(peer2.event_receiver);

    // Dial so that the peers have each other in their DHTs, the direction doesn't matter
    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    for (expected_request, expected_response) in [
        (
            Request::GetBlockHeaders(Faker.fake::<GetBlockHeaders>()),
            Response::BlockHeaders(Faker.fake::<BlockHeaders>()),
        ),
        (
            Request::GetBlockBodies(Faker.fake::<GetBlockBodies>()),
            Response::BlockBodies(Faker.fake::<BlockBodies>()),
        ),
        (
            Request::GetStateDiffs(Faker.fake::<GetStateDiffs>()),
            Response::StateDiffs(Faker.fake::<StateDiffs>()),
        ),
        (
            Request::Status(Faker.fake::<Status>()),
            Response::Status(Faker.fake::<Status>()),
        ),
    ] {
        let expected_request_cloned = expected_request.clone();
        let expected_response_cloned = expected_response.clone();
        let client2 = peer2.client.clone();

        tokio::spawn(async move {
            let resp = client2
                .send_sync_request(peer1.peer_id, expected_request_cloned)
                .await
                .unwrap();
            assert_eq!(resp, expected_response_cloned);
        });

        let (request, resp_channel) = peer1_inbound_sync_requests.recv().await.unwrap();
        assert_eq!(request, expected_request);
        peer1
            .client
            .send_sync_response(resp_channel, expected_response)
            .await;
    }

    // Also test the client method used specifically to send status requests
    let expected_sync_request = Faker.fake::<Status>();
    peer2
        .client
        .send_sync_status_request(peer1.peer_id, expected_sync_request.clone())
        .await;
    let (request, _) = peer1_inbound_sync_requests.recv().await.unwrap();
    assert_eq!(request, Request::Status(expected_sync_request));
}

#[test_log::test(tokio::test)]
async fn sync_status_events_and_periodic() {
    use assert_matches::assert_matches;

    let _ = env_logger::builder().is_test(true).try_init();

    let periodic_cfg = PeriodicTaskConfig {
        bootstrap: BootstrapConfig {
            period: Duration::from_secs(60 * 60),
            start_offset: Duration::from_secs(60 * 60),
        },
        status_period: Duration::from_millis(100),
    };

    let mut peer1 = TestPeer::new(periodic_cfg);
    let mut peer2 = TestPeer::new(periodic_cfg);

    let addr1 = peer1.start_listening().await.unwrap();
    let addr2 = peer2.start_listening().await.unwrap();

    tracing::info!(%peer1.peer_id, %addr1, "peer1");
    tracing::info!(%peer2.peer_id, %addr2, "peer2");
    tracing::info!("peer1 < peer2 = {}", peer1.peer_id < peer2.peer_id);

    #[derive(Debug)]
    enum FilteredEvent {
        SyncPeerConnected { from: PeerId },
        SyncPeerRequestStatus { from: PeerId },
    }

    let filter = move |event| match event {
        Event::SyncPeerConnected { peer_id } => {
            Some(FilteredEvent::SyncPeerConnected { from: peer_id })
        }
        Event::SyncPeerRequestStatus { peer_id } => {
            Some(FilteredEvent::SyncPeerRequestStatus { from: peer_id })
        }
        _ => None,
    };

    let mut peer1_events = filter_events(peer1.event_receiver, filter);
    let mut peer2_events = filter_events(peer2.event_receiver, filter);

    // Dial so that the peers have each other in their DHTs, the direction doesn't matter
    peer1
        .client
        .dial(peer2.peer_id, addr2.clone())
        .await
        .unwrap();

    assert_matches!(peer1_events.recv().await.unwrap(), FilteredEvent::SyncPeerConnected { from } => { assert_eq!(from, peer2.peer_id)});
    assert_matches!(peer2_events.recv().await.unwrap(), FilteredEvent::SyncPeerConnected { from } => { assert_eq!(from, peer1.peer_id)});

    // Only one of the peers will trigger a periodic sync status request
    // depending on which has the lower peer id
    tokio::select! {
        e = peer1_events.recv() => {
            assert_matches!(e, Some(FilteredEvent::SyncPeerRequestStatus { from }) => { assert_eq!(from, peer2.peer_id)});
            assert!(peer1.peer_id < peer2.peer_id);
        }
        e = peer2_events.recv() => {
            assert_matches!(e, Some(FilteredEvent::SyncPeerRequestStatus { from }) => { assert_eq!(from, peer1.peer_id)});
            assert!(peer2.peer_id < peer1.peer_id);
        }
    }
}
