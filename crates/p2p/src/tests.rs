use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use fake::{Fake, Faker};
use futures::{SinkExt, StreamExt};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use p2p_proto::block::{
    BlockBodiesRequest, BlockBodiesResponse, BlockHeadersRequest, BlockHeadersResponse, NewBlock,
};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::receipt::{ReceiptsRequest, ReceiptsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::ChainId;
use rstest::rstest;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use crate::{BootstrapConfig, Event, EventReceiver, Peers, PeriodicTaskConfig, TestEvent};

#[allow(dead_code)]
#[derive(Debug)]
struct TestPeer {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub peers: Arc<RwLock<Peers>>,
    pub client: crate::Client,
    pub event_receiver: crate::EventReceiver,
    pub main_loop_jh: JoinHandle<()>,
}

impl TestPeer {
    #[must_use]
    pub fn new(periodic_cfg: PeriodicTaskConfig) -> Self {
        let keypair = Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let peers: Arc<RwLock<Peers>> = Default::default();
        let (client, event_receiver, main_loop) = crate::new(
            keypair.clone(),
            peers.clone(),
            periodic_cfg,
            ChainId::GOERLI_TESTNET,
        );
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
        while let Some(event) = event_receiver.recv().await {
            if let Some(data) = f(event) {
                tx.try_send(data).unwrap();
            }
        }
    });

    rx
}

/// Wait for a specific event to happen.
async fn wait_for_event<T: Debug + Send + 'static>(
    event_receiver: &mut EventReceiver,
    mut f: impl FnMut(Event) -> Option<T>,
) -> Option<T> {
    while let Some(event) = event_receiver.recv().await {
        if let Some(data) = f(event) {
            return Some(data);
        }
    }
    None
}

/// [`MainLoop`](p2p::MainLoop)'s event channel size is 1, so we need to consume
/// all events as soon as they're sent otherwise the main loop will stall
fn consume_events(mut event_receiver: EventReceiver) {
    tokio::spawn(async move { while (event_receiver.recv().await).is_some() {} });
}

async fn create_peers() -> (TestPeer, TestPeer) {
    let mut server = TestPeer::default();
    let client = TestPeer::default();

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

async fn server_to_client() -> (TestPeer, TestPeer) {
    create_peers().await
}

async fn client_to_server() -> (TestPeer, TestPeer) {
    let (s, c) = create_peers().await;
    (c, s)
}

#[test_log::test(tokio::test)]
async fn dial() {
    let _ = env_logger::builder().is_test(true).try_init();
    // tokio::time::pause() does not make a difference
    let peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    let peers_of1 = peer1.connected().await;
    let peers_of2 = peer2.connected().await;

    assert_eq!(peers_of1, [peer2.peer_id].into());
    assert_eq!(peers_of2, [peer1.peer_id].into());
}

#[test_log::test(tokio::test)]
async fn disconnect() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    let peers_of1 = peer1.connected().await;
    let peers_of2 = peer2.connected().await;

    assert_eq!(peers_of1, [peer2.peer_id].into());
    assert_eq!(peers_of2, [peer1.peer_id].into());

    peer2.client.disconnect(peer1.peer_id).await.unwrap();

    wait_for_event(&mut peer1.event_receiver, move |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote }) if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.event_receiver, move |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote }) if remote == peer1.peer_id => Some(()),
        _ => None,
    })
    .await;

    assert!(peer1.connected().await.is_empty());
    assert!(peer2.connected().await.is_empty());
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
        direct_connection_timeout: Duration::from_millis(500),
        relay_connection_timeout: Duration::from_millis(500),
    };
    let mut boot = TestPeer::new(periodic_cfg);
    let mut peer1 = TestPeer::new(periodic_cfg);
    let mut peer2 = TestPeer::new(periodic_cfg);

    let mut boot_addr = boot.start_listening().await.unwrap();
    boot_addr.push(Protocol::P2p(boot.peer_id));

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

/// Test that if a peer attempts to reconnect too quickly, the connection is closed.
#[test_log::test(tokio::test)]
async fn reconnect_too_quickly() {
    const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);
    let periodic_cfg = PeriodicTaskConfig {
        bootstrap: BootstrapConfig {
            period: Duration::from_millis(500),
            // Bootstrapping can cause redials, so set the offset to a high value.
            start_offset: Duration::from_secs(3),
        },
        direct_connection_timeout: CONNECTION_TIMEOUT,
        relay_connection_timeout: Duration::from_millis(500),
    };

    let mut peer1 = TestPeer::new(periodic_cfg);
    let mut peer2 = TestPeer::new(periodic_cfg);

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    // Open the connection.
    peer1
        .client
        .dial(peer2.peer_id, addr2.clone())
        .await
        .unwrap();

    wait_for_event(&mut peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionEstablished { remote, .. }) if remote == peer2.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionEstablished { remote, .. }) if remote == peer1.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    let peers_of1 = peer1.connected().await;
    let peers_of2 = peer2.connected().await;

    assert_eq!(peers_of1, [peer2.peer_id].into());
    assert_eq!(peers_of2, [peer1.peer_id].into());

    // Close the connection.
    peer1.client.disconnect(peer2.peer_id).await.unwrap();

    wait_for_event(&mut peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote }) if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote }) if remote == peer1.peer_id => Some(()),
        _ => None,
    })
    .await;

    // Attempt to immediately reconnect.
    peer1
        .client
        .dial(peer2.peer_id, addr2.clone())
        .await
        .unwrap();

    // The peer gets disconnected without completing the connection establishment handler.
    wait_for_event(&mut peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote }) if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote }) if remote == peer1.peer_id => Some(()),
        _ => None,
    })
    .await;

    // Attempt to reconnect after the timeout.
    tokio::time::sleep(CONNECTION_TIMEOUT).await;
    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    // The connection is established.
    wait_for_event(&mut peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionEstablished { remote, .. }) if remote == peer2.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionEstablished { remote, .. }) if remote == peer1.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;
}

#[rstest]
#[case::server_to_client(server_to_client().await)]
#[case::client_to_server(client_to_server().await)]
#[test_log::test(tokio::test)]
async fn provide_capability(#[case] peers: (TestPeer, TestPeer)) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peer1, peer2) = peers;

    let mut peer1_started_providing = filter_events(peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::StartProvidingCompleted(_)) => Some(()),
        _ => None,
    });
    consume_events(peer2.event_receiver);

    peer1.client.provide_capability("blah").await.unwrap();
    peer1_started_providing.recv().await;

    // Apparently sometimes still not yet providing at this point and there's
    // no other event to rely on
    tokio::time::sleep(Duration::from_millis(500)).await;

    let providers = peer2.client.get_capability_providers("blah").await.unwrap();

    assert_eq!(providers, [peer1.peer_id].into());
}

#[rstest]
#[case::server_to_client(server_to_client().await)]
#[case::client_to_server(client_to_server().await)]
#[test_log::test(tokio::test)]
async fn subscription_and_propagation(#[case] peers: (TestPeer, TestPeer)) {
    let _ = env_logger::builder().is_test(true).try_init();
    let (peer1, peer2) = peers;

    let mut peer2_subscribed_to_peer1 = filter_events(peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::Subscribed { .. }) => Some(()),
        _ => None,
    });

    let mut propagated_to_peer2 = filter_events(peer2.event_receiver, |event| match event {
        Event::BlockPropagation { new_block, .. } => Some(new_block),
        _ => None,
    });

    const TOPIC: &str = "TOPIC";

    peer2.client.subscribe_topic(TOPIC).await.unwrap();
    peer2_subscribed_to_peer1.recv().await;

    let expected = Faker.fake::<NewBlock>();

    peer1.client.publish(TOPIC, expected.clone()).await.unwrap();

    let msg = propagated_to_peer2.recv().await.unwrap();

    assert_eq!(msg, expected);
}

/// Defines a sync test case named [`$test_name`], where there are 2 peers:
/// - peer2 sends a request to peer1
/// - peer1 responds with a random number of responses
/// - request is of type [`$req_type`] and is sent using [`$req_fn`]
/// - response is of type [`$res_type`]
/// - [`$event_variant`] is the event that tells peer1 that it received peer2's request
macro_rules! define_test {
    ($test_name:ident, $req_type:ty, $res_type:ty, $event_variant:ident, $req_fn:ident) => {
        #[rstest]
        #[case::server_to_client(server_to_client().await)]
        #[case::client_to_server(client_to_server().await)]
        #[test_log::test(tokio::test)]
        async fn $test_name(#[case] peers: (TestPeer, TestPeer)) {
            let _ = env_logger::builder().is_test(true).try_init();
            let (peer1, peer2) = peers;
            // Fake some request for peer2 to send to peer1
            let expected_request = Faker.fake::<$req_type>();

            // Filter peer1's events to fish out the request from peer2 and the channel that
            // peer1 will use to send the responses
            // This is also to keep peer1's event loop going
            let mut tx_ready = filter_events(peer1.event_receiver, move |event| match event {
                Event::$event_variant {
                    from,
                    channel,
                    request: actual_request,
                } => {
                    // Peer 1 should receive the request from peer2
                    assert_eq!(from, peer2.peer_id);
                    // Received request should match what peer2 sent
                    assert_eq!(expected_request, actual_request);
                    Some(channel)
                }
                _ => None,
            });

            // This is to keep peer2's event loop going
            consume_events(peer2.event_receiver);

            // Peer2 sends the request to peer1, and waits for the response receiver
            let mut rx = peer2
                .client
                .$req_fn(peer1.peer_id, expected_request)
                .await
                .expect(&format!(
                    "sending request using: {}, line: {}",
                    std::stringify!($req_fn),
                    line!()
                ));

            // Peer1 waits for response channel to be ready
            let mut tx = tx_ready.recv().await.expect(&format!(
                "waiting for response channel to be ready, line: {}",
                line!()
            ));

            // Peer1 sends a random number of responses to Peer2
            for _ in 0usize..(1..100).fake() {
                let expected_response = Faker.fake::<$res_type>();
                // Peer1 sends the response
                tx.send(expected_response.clone())
                    .await
                    .expect(&format!("sending expected response, line: {}", line!()));
                // Peer2 waits for the response
                let actual_response = rx
                    .next()
                    .await
                    .expect(&format!("receiving actual response, line: {}", line!()));
                // See if they match
                assert_eq!(
                    expected_response,
                    actual_response,
                    "response mismatch, line: {}",
                    line!()
                );
            }
        }
    };
}

define_test!(
    sync_headers,
    BlockHeadersRequest,
    BlockHeadersResponse,
    InboundHeadersSyncRequest,
    send_headers_sync_request
);

define_test!(
    sync_bodies,
    BlockBodiesRequest,
    BlockBodiesResponse,
    InboundBodiesSyncRequest,
    send_bodies_sync_request
);

define_test!(
    sync_transactions,
    TransactionsRequest,
    TransactionsResponse,
    InboundTransactionsSyncRequest,
    send_transactions_sync_request
);

define_test!(
    sync_receipts,
    ReceiptsRequest,
    ReceiptsResponse,
    InboundReceiptsSyncRequest,
    send_receipts_sync_request
);

define_test!(
    sync_events,
    EventsRequest,
    EventsResponse,
    InboundEventsSyncRequest,
    send_events_sync_request
);
