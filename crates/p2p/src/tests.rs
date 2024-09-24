use std::fmt::Debug;
use std::time::Duration;

use fake::{Fake, Faker};
use futures::{FutureExt, SinkExt, StreamExt};
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;
use p2p_proto::class::{ClassesRequest, ClassesResponse};
use p2p_proto::event::{EventsRequest, EventsResponse};
use p2p_proto::header::{BlockHeadersRequest, BlockHeadersResponse, NewBlock};
use p2p_proto::state::{StateDiffsRequest, StateDiffsResponse};
use p2p_proto::transaction::{TransactionsRequest, TransactionsResponse};
use pathfinder_common::ChainId;
use rstest::rstest;

use crate::sync::codec;
use crate::test_utils::peer::TestPeer;
use crate::{Config, Event, EventReceiver, RateLimit, TestEvent};

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

/// Consume all events that have accumulated for the peer so far. You don't care
/// about any of those events in the queue __right now__, but later you may do
/// something that triggers new events for this peer, which you may care for.
async fn consume_accumulated_events(event_receiver: &mut EventReceiver) {
    while event_receiver.try_recv().is_ok() {}
}

/// Consume all events from a peer to keep its main loop going. You don't care
/// about any of those events.
///
/// [`MainLoop`](p2p::MainLoop)'s event channel size is 1, so we need to consume
/// all events as soon as they're sent otherwise the main loop will stall
fn consume_all_events_forever(mut event_receiver: EventReceiver) {
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
    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    consume_accumulated_events(&mut peer1.event_receiver).await;

    let peers_of1: Vec<_> = peer1.connected().await.into_keys().collect();
    let peers_of2: Vec<_> = peer2.connected().await.into_keys().collect();

    assert_eq!(peers_of1, vec![peer2.peer_id]);
    assert_eq!(peers_of2, vec![peer1.peer_id]);
}

#[test_log::test(tokio::test)]
async fn disconnect() {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    consume_accumulated_events(&mut peer1.event_receiver).await;

    let peers_of1: Vec<_> = peer1.connected().await.into_keys().collect();
    let peers_of2: Vec<_> = peer2.connected().await.into_keys().collect();

    assert_eq!(peers_of1, vec![peer2.peer_id]);
    assert_eq!(peers_of2, vec![peer1.peer_id]);

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

    const BOOTSTRAP_PERIOD: Duration = Duration::from_millis(500);
    let cfg = Config {
        bootstrap_period: BOOTSTRAP_PERIOD,
        ..Config::for_test()
    };
    let mut boot = TestPeer::new(cfg.clone());
    let mut peer1 = TestPeer::new(cfg.clone());
    let mut peer2 = TestPeer::new(cfg.clone());

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
    peer2
        .client
        .dial(boot.peer_id, boot_addr.clone())
        .await
        .unwrap();

    let filter_kademlia_bootstrap_completed = |event| match event {
        Event::Test(TestEvent::KademliaBootstrapCompleted(_)) => Some(()),
        _ => None,
    };

    consume_all_events_forever(boot.event_receiver);

    let peer_id2 = peer2.peer_id;

    let peer2_added_to_dht_of_peer1 =
        wait_for_event(&mut peer1.event_receiver, move |event| match event {
            Event::Test(TestEvent::PeerAddedToDHT { remote }) if remote == peer_id2 => Some(()),
            _ => None,
        });

    tokio::join!(peer2_added_to_dht_of_peer1, async {
        wait_for_event(
            &mut peer2.event_receiver,
            filter_kademlia_bootstrap_completed,
        )
        .await;
        wait_for_event(
            &mut peer2.event_receiver,
            filter_kademlia_bootstrap_completed,
        )
        .await;
    });

    consume_all_events_forever(peer1.event_receiver);

    assert_eq!(
        boot.client.for_test().get_peers_from_dht().await,
        [peer1.peer_id, peer2.peer_id].into()
    );
    assert_eq!(
        peer1.client.for_test().get_peers_from_dht().await,
        [boot.peer_id, peer2.peer_id].into()
    );
    assert_eq!(
        peer2.client.for_test().get_peers_from_dht().await,
        [boot.peer_id, peer1.peer_id].into()
    );

    // The peer keeps attempting the bootstrap because the low watermark is not
    // reached, but there are no new peers to connect to.

    wait_for_event(
        &mut peer2.event_receiver,
        filter_kademlia_bootstrap_completed,
    )
    .await;

    assert_eq!(
        boot.client.for_test().get_peers_from_dht().await,
        [peer1.peer_id, peer2.peer_id].into()
    );
    assert_eq!(
        peer1.client.for_test().get_peers_from_dht().await,
        [boot.peer_id, peer2.peer_id].into()
    );
    assert_eq!(
        peer2.client.for_test().get_peers_from_dht().await,
        [boot.peer_id, peer1.peer_id].into()
    );
}

/// Test that if a peer attempts to reconnect too quickly, the connection is
/// closed.
#[test_log::test(tokio::test)]
async fn reconnect_too_quickly() {
    const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);
    let cfg = Config {
        direct_connection_timeout: CONNECTION_TIMEOUT,
        ..Config::for_test()
    };

    let mut peer1 = TestPeer::new(cfg.clone());
    let mut peer2 = TestPeer::new(cfg);

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

    let peers_of1: Vec<_> = peer1.connected().await.into_keys().collect();
    let peers_of2: Vec<_> = peer2.connected().await.into_keys().collect();

    assert_eq!(peers_of1, vec![peer2.peer_id]);
    assert_eq!(peers_of2, vec![peer1.peer_id]);

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
    let result = peer1.client.dial(peer2.peer_id, addr2.clone()).await;
    assert!(result.is_err());

    // Attempt to reconnect after the timeout.
    tokio::time::sleep(CONNECTION_TIMEOUT).await;
    let result = peer1.client.dial(peer2.peer_id, addr2).await;
    assert!(result.is_ok());

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

/// Test that each peer accepts at most one connection from any other peer, and
/// duplicate connections are closed.
#[test_log::test(tokio::test)]
async fn duplicate_connection() {
    const CONNECTION_TIMEOUT: Duration = Duration::from_millis(50);
    let cfg = Config {
        direct_connection_timeout: CONNECTION_TIMEOUT,
        ..Config::for_test()
    };
    let keypair = Keypair::generate_ed25519();
    let mut peer1 = TestPeer::with_keypair(keypair.clone(), cfg.clone());
    let mut peer1_copy = TestPeer::with_keypair(keypair.clone(), cfg.clone());
    let mut peer2 = TestPeer::new(cfg);

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

    // Ensure that the connection timeout has passed, so this is not the reason why
    // the connection is getting closed.
    tokio::time::sleep(CONNECTION_TIMEOUT).await;

    // Try to open another connection using the same peer ID and IP address (in this
    // case, localhost).
    peer1_copy
        .client
        .dial(peer2.peer_id, addr2.clone())
        .await
        .unwrap();

    wait_for_event(&mut peer1_copy.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionEstablished { remote, .. }) if remote == peer2.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    wait_for_event(&mut peer1_copy.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote, .. }) if remote == peer2.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    assert!(peer1_copy.connected().await.is_empty());
    assert!(peer1.connected().await.contains_key(&peer2.peer_id));
}

/// Ensure that outbound peers marked as not useful get evicted if new outbound
/// connections are attempted.
#[test_log::test(tokio::test)]
async fn outbound_peer_eviction() {
    let cfg = Config {
        max_inbound_direct_peers: 2,
        max_inbound_relayed_peers: 0,
        max_outbound_peers: 2,
        ..Config::for_test()
    };

    let mut peer = TestPeer::new(cfg.clone());
    let mut outbound1 = TestPeer::new(cfg.clone());
    let mut outbound2 = TestPeer::new(cfg.clone());
    let mut outbound3 = TestPeer::new(cfg.clone());
    let mut outbound4 = TestPeer::new(cfg.clone());
    let inbound1 = TestPeer::new(cfg.clone());
    let inbound2 = TestPeer::new(cfg);

    let peer_addr = peer.start_listening().await.unwrap();
    tracing::info!(%peer.peer_id, %peer_addr);
    let outbound_addr1 = outbound1.start_listening().await.unwrap();
    tracing::info!(%outbound1.peer_id, %outbound_addr1);
    let outbound_addr2 = outbound2.start_listening().await.unwrap();
    tracing::info!(%outbound2.peer_id, %outbound_addr2);
    let outbound_addr3 = outbound3.start_listening().await.unwrap();
    tracing::info!(%outbound3.peer_id, %outbound_addr3);
    let outbound_addr4 = outbound4.start_listening().await.unwrap();
    tracing::info!(%outbound4.peer_id, %outbound_addr4);

    consume_all_events_forever(outbound1.event_receiver);
    consume_all_events_forever(outbound2.event_receiver);
    consume_all_events_forever(outbound3.event_receiver);
    consume_all_events_forever(outbound4.event_receiver);
    consume_all_events_forever(inbound1.event_receiver);

    // Open one inbound connection. This connection is never touched.
    inbound1
        .client
        .dial(peer.peer_id, peer_addr.clone())
        .await
        .unwrap();

    // We can open two connections because the limit is 2.
    peer.client
        .dial(outbound1.peer_id, outbound_addr1.clone())
        .await
        .unwrap();
    peer.client
        .dial(outbound2.peer_id, outbound_addr2.clone())
        .await
        .unwrap();

    consume_accumulated_events(&mut peer.event_receiver).await;

    // Trying to open another one fails, because no peers are marked as not useful,
    // and hence no peer can be evicted.
    let result = peer
        .client
        .dial(outbound3.peer_id, outbound_addr3.clone())
        .await;
    assert!(result.is_err());

    let peers = peer.connected().await;
    assert_eq!(peers.len(), 3);
    assert!(peers.contains_key(&outbound1.peer_id));
    assert!(peers.contains_key(&outbound2.peer_id));
    assert!(peers.contains_key(&inbound1.peer_id));

    // Mark one of the connected peers as not useful.
    peer.client.not_useful(outbound1.peer_id).await;

    // Now the connection to outbound3 can be opened, because outbound1 is marked as
    // not useful and will be evicted.
    peer.client
        .dial(outbound3.peer_id, outbound_addr3.clone())
        .await
        .unwrap();

    // No longer connected to outbound1.
    let peers = peer.connected().await;
    assert_eq!(peers.len(), 3);
    assert!(!peers.contains_key(&outbound1.peer_id));
    assert!(peers.contains_key(&outbound2.peer_id));
    assert!(peers.contains_key(&outbound3.peer_id));
    assert!(peers.contains_key(&inbound1.peer_id));

    // Ensure that outbound1 actually got disconnected.
    wait_for_event(&mut peer.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote, .. }) if remote == outbound1.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await
    .unwrap();

    // The limit is reached again, so no new connections can be opened.
    let result = peer
        .client
        .dial(outbound4.peer_id, outbound_addr4.clone())
        .await;
    assert!(result.is_err());

    // Inbound connections can still be opened.
    inbound2.client.dial(peer.peer_id, peer_addr).await.unwrap();

    let peers = peer.connected().await;
    assert_eq!(peers.len(), 4);
    assert!(!peers.contains_key(&outbound1.peer_id));
    assert!(peers.contains_key(&outbound2.peer_id));
    assert!(peers.contains_key(&outbound3.peer_id));
    assert!(peers.contains_key(&inbound1.peer_id));
    assert!(peers.contains_key(&inbound2.peer_id));
}

/// Ensure that inbound peers get evicted if new inbound connections
/// are attempted.
#[test_log::test(tokio::test)]
async fn inbound_peer_eviction() {
    let cfg = Config {
        max_inbound_direct_peers: 25,
        max_inbound_relayed_peers: 0,
        max_outbound_peers: 100,
        ..Config::for_test()
    };

    let mut peer = TestPeer::new(cfg.clone());
    let inbound_peers = (0..26)
        .map(|_| TestPeer::new(cfg.clone()))
        .collect::<Vec<_>>();
    let mut outbound1 = TestPeer::new(cfg);

    let peer_addr = peer.start_listening().await.unwrap();
    tracing::info!(%peer.peer_id, %peer_addr);
    let outbound_addr1 = outbound1.start_listening().await.unwrap();
    tracing::info!(%outbound1.peer_id, %outbound_addr1);

    // Open one outbound connection. This connection is never touched.
    peer.client
        .dial(outbound1.peer_id, outbound_addr1.clone())
        .await
        .unwrap();

    // We can open 25 connections because the limit is 25.
    for inbound_peer in inbound_peers.iter().take(25) {
        inbound_peer
            .client
            .dial(peer.peer_id, peer_addr.clone())
            .await
            .unwrap();
    }

    let connected = peer.connected().await;
    // 25 inbound and 1 outbound peer.
    assert_eq!(connected.len(), 26);
    assert!(connected.contains_key(&outbound1.peer_id));

    consume_accumulated_events(&mut peer.event_receiver).await;

    // Trying to open another one causes an eviction.
    inbound_peers
        .last()
        .unwrap()
        .client
        .dial(peer.peer_id, peer_addr.clone())
        .await
        .unwrap();

    // Ensure that a peer got disconnected.
    let disconnected = wait_for_event(&mut peer.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote, .. })
            if inbound_peers.iter().take(25).any(|p| p.peer_id == remote) =>
        {
            Some(remote)
        }
        _ => None,
    })
    .await
    .unwrap();

    let connected = peer.connected().await;
    // 25 inbound and 1 outbound peer.
    assert_eq!(connected.len(), 26);
    assert!(!connected.contains_key(&disconnected));
    assert!(connected.contains_key(&inbound_peers.last().unwrap().peer_id));
    assert!(connected.contains_key(&outbound1.peer_id));
}

/// Ensure that evicted peers can't reconnect too quickly.
#[ignore = "TODO fix eviction and low watermark logic after updating to libp2p 0.54.1"]
#[test_log::test(tokio::test)]
async fn evicted_peer_reconnection() {
    let cfg = Config {
        max_inbound_direct_peers: 1000,
        max_inbound_relayed_peers: 0,
        max_outbound_peers: 1,
        ..Config::for_test()
    };

    let mut peer1 = TestPeer::new(cfg.clone());
    let mut peer2 = TestPeer::new(cfg.clone());
    let mut peer3 = TestPeer::new(cfg);

    let addr1 = peer1.start_listening().await.unwrap();
    tracing::info!(%peer1.peer_id, %addr1);
    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);
    let addr3 = peer3.start_listening().await.unwrap();
    tracing::info!(%peer3.peer_id, %addr3);

    // Connect peer1 to peer2, then to peer3. Because the outbound connection limit
    // is 1, peer2 will be evicted when peer1 connects to peer3.
    peer1
        .client
        .dial(peer2.peer_id, addr2.clone())
        .await
        .unwrap();
    peer1.client.not_useful(peer2.peer_id).await;
    peer1.client.dial(peer3.peer_id, addr3).await.unwrap();

    // Check that peer2 got evicted.
    wait_for_event(&mut peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote, .. }) if remote == peer2.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    // Mark peer3 as not useful, and hence a candidate for eviction.
    peer1.client.not_useful(peer3.peer_id).await;

    // Try to reconnect too quickly.
    let result = peer1.client.dial(peer2.peer_id, addr2.clone()).await;
    assert!(result.is_err());

    consume_accumulated_events(&mut peer2.event_receiver).await;

    // In this case there is no peer ID when connecting, so the connection gets
    // closed after being established.
    peer2
        .client
        .dial(peer1.peer_id, addr1.clone())
        .await
        .unwrap();
    wait_for_event(&mut peer2.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote, .. }) if remote == peer1.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;

    // peer2 can be reconnected after a timeout.
    tokio::time::sleep(Duration::from_secs(1)).await;
    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    // peer3 gets evicted.
    wait_for_event(&mut peer1.event_receiver, |event| match event {
        Event::Test(TestEvent::ConnectionClosed { remote, .. }) if remote == peer3.peer_id => {
            Some(())
        }
        _ => None,
    })
    .await;
}

/// Test that peers can only connect if they are whitelisted.
#[test_log::test(tokio::test)]
async fn ip_whitelist() {
    let cfg = Config {
        ip_whitelist: vec!["127.0.0.2/32".parse().unwrap()],
        ..Config::for_test()
    };
    let mut peer1 = TestPeer::new(cfg.clone());
    let peer2 = TestPeer::new(cfg.clone());

    let addr1 = peer1.start_listening().await.unwrap();
    tracing::info!(%peer1.peer_id, %addr1);

    consume_all_events_forever(peer2.event_receiver);

    // Can't open the connection because peer2 is bound to 127.0.0.1 and peer1 only
    // allows 127.0.0.2.
    let result = peer2.client.dial(peer1.peer_id, addr1.clone()).await;
    assert!(result.is_err());

    // Start another peer accepting connections from 127.0.0.1.
    let cfg = Config {
        ip_whitelist: vec!["127.0.0.1/32".parse().unwrap()],
        ..Config::for_test()
    };
    let mut peer3 = TestPeer::new(cfg);

    let addr3 = peer3.start_listening().await.unwrap();
    tracing::info!(%peer3.peer_id, %addr3);

    // Connection can be opened because peer3 allows connections from 127.0.0.1.
    let result = peer2.client.dial(peer3.peer_id, addr3.clone()).await;
    assert!(result.is_ok());
}

/// Check that inbound connections get rate limited.
#[test_log::test(tokio::test)]
async fn rate_limit() {
    const RATE_LIMIT_INTERVAL: Duration = Duration::from_secs(1);

    let cfg = Config {
        inbound_connections_rate_limit: RateLimit {
            max: 2,
            interval: RATE_LIMIT_INTERVAL,
        },
        ..Config::for_test()
    };

    let mut peer1 = TestPeer::new(cfg.clone());
    let peer2 = TestPeer::new(cfg.clone());
    let peer3 = TestPeer::new(cfg.clone());
    let peer4 = TestPeer::new(cfg);

    let addr1 = peer1.start_listening().await.unwrap();
    tracing::info!(%peer1.peer_id, %addr1);

    consume_all_events_forever(peer1.event_receiver);
    consume_all_events_forever(peer2.event_receiver);
    consume_all_events_forever(peer3.event_receiver);
    consume_all_events_forever(peer4.event_receiver);

    // Two connections can be opened, but the third one is rate limited.

    peer2
        .client
        .dial(peer1.peer_id, addr1.clone())
        .await
        .unwrap();
    peer3
        .client
        .dial(peer1.peer_id, addr1.clone())
        .await
        .unwrap();

    let result = peer4.client.dial(peer1.peer_id, addr1.clone()).await;
    assert!(result.is_err());
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
    consume_all_events_forever(peer2.event_receiver);

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

mod successful_sync {
    use super::*;

    /// Defines a test case named [`$test_name`], where there are 2 peers:
    /// - peer2 sends a request to peer1
    /// - peer1 responds with a random number of responses
    /// - request is of type [`$req_type`] and is sent using [`$req_fn`]
    /// - response is of type [`$res_type`]
    /// - [`$event_variant`] is the event that tells peer1 that it received
    ///   peer2's request
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
                consume_all_events_forever(peer2.event_receiver);

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
                        .expect(&format!("receiving actual response, line: {}", line!()))
                        .expect(&format!("response should be Ok(), line: {}", line!()));
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
        sync_classes,
        ClassesRequest,
        ClassesResponse,
        InboundClassesSyncRequest,
        send_classes_sync_request
    );

    define_test!(
        sync_state_diffs,
        StateDiffsRequest,
        StateDiffsResponse,
        InboundStateDiffsSyncRequest,
        send_state_diffs_sync_request
    );

    define_test!(
        sync_transactions,
        TransactionsRequest,
        TransactionsResponse,
        InboundTransactionsSyncRequest,
        send_transactions_sync_request
    );

    define_test!(
        sync_events,
        EventsRequest,
        EventsResponse,
        InboundEventsSyncRequest,
        send_events_sync_request
    );
}

mod propagate_codec_errors_to_caller {
    use super::*;
    use crate::test_utils::sync::TypeErasedReadFactory;

    enum BadPeer {
        Server,
        Client,
    }

    enum BadCodec {
        Headers,
        Transactions,
        StateDiffs,
        Classes,
        Events,
    }

    fn error_factory<T>() -> TypeErasedReadFactory<T> {
        Box::new(|| {
            Box::new(|_| {
                async {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "stream error",
                    ))
                }
                .boxed()
            })
        })
    }

    async fn create_peers(bad_peer: BadPeer, bad_codec: BadCodec) -> (TestPeer, TestPeer) {
        let good = TestPeer::default();

        let keypair = Keypair::generate_ed25519();
        let cfg = Config::for_test();
        let chain_id = ChainId::SEPOLIA_TESTNET;

        let bb = crate::behaviour::Builder::new(keypair.clone(), chain_id, cfg.clone());
        let bb = match bad_codec {
            BadCodec::Headers => bb.header_sync_behaviour(p2p_stream::Behaviour::with_codec(
                codec::Headers::for_test().set_read_response_factory(error_factory()),
                Default::default(),
            )),
            BadCodec::Transactions => {
                bb.transaction_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::Transactions::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::StateDiffs => {
                bb.state_diff_sync_behaviour(p2p_stream::Behaviour::with_codec(
                    codec::StateDiffs::for_test().set_read_response_factory(error_factory()),
                    Default::default(),
                ))
            }
            BadCodec::Classes => bb.class_sync_behaviour(p2p_stream::Behaviour::with_codec(
                codec::Classes::for_test().set_read_response_factory(error_factory()),
                Default::default(),
            )),
            BadCodec::Events => bb.event_sync_behaviour(p2p_stream::Behaviour::with_codec(
                codec::Events::for_test().set_read_response_factory(error_factory()),
                Default::default(),
            )),
        };

        let p2p_builder =
            crate::Builder::new(keypair.clone(), cfg.clone(), chain_id).behaviour_builder(bb);
        let bad = TestPeer::builder()
            .p2p_builder(p2p_builder)
            .build(keypair, cfg);

        let (mut server, client) = match bad_peer {
            BadPeer::Server => (bad, good),
            BadPeer::Client => (good, bad),
        };

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

    async fn server_to_bad_client(bad_codec: BadCodec) -> (TestPeer, TestPeer) {
        create_peers(BadPeer::Client, bad_codec).await
    }

    async fn client_to_bad_server(bad_codec: BadCodec) -> (TestPeer, TestPeer) {
        let (s, c) = create_peers(BadPeer::Server, bad_codec).await;
        (c, s)
    }

    /// Defines a test case named [`$test_name`], where there are 2 peers:
    /// - peer2 sends a request to peer1
    /// - peer1 responds with a random response
    /// - peer2's codec is mocked to fail upon reception, simulating peer1
    ///   sending garbage in response
    /// - request is of type [`$req_type`] and is sent using [`$req_fn`]
    /// - response is of type [`$res_type`]
    /// - [`$event_variant`] is the event that tells peer1 that it received
    ///   peer2's request
    /// - [`$bad_codec`] is the codec that will be mocked to fail upon reception
    macro_rules! define_test {
        ($test_name:ident, $req_type:ty, $res_type:ty, $event_variant:ident, $req_fn:ident, $bad_codec:expr) => {
            #[rstest]
            #[case::server_to_client(server_to_bad_client($bad_codec).await)]
            #[case::client_to_server(client_to_bad_server($bad_codec).await)]
            #[test_log::test(tokio::test)]
            async fn $test_name(#[case] peers: (TestPeer, TestPeer)) {
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
                consume_all_events_forever(peer2.event_receiver);

                // Peer2 sends the request to peer1, and waits for the response receiver
                let mut rx = peer2
                    .client
                    .$req_fn(peer1.peer_id, expected_request)
                    .await
                    .unwrap_or_else(|_| {
                        panic!(
                            "sending request using: {}, line: {}",
                            std::stringify!($req_fn),
                            // "TODO",
                            line!()
                        )
                    });

                // Peer1 waits for response channel to be ready
                let mut tx = tx_ready.recv().await.unwrap_or_else(|| {
                    panic!(
                        "waiting for response channel to be ready, line: {}",
                        line!()
                    )
                });

                let expected_response = Faker.fake::<$res_type>();
                // Peer1 sends 1 response, but peer2's codec is mocked to fail upon reception
                // simulating peer1 sending garbage in response
                tx.send(expected_response.clone())
                    .await
                    .unwrap_or_else(|_| panic!("sending expected response, line: {}", line!()));

                // Peer2 waits for the response
                let actual_response = rx.next().await.unwrap();
                eprintln!("actual_response {:?}", actual_response);
                assert!(
                    matches!(actual_response, Err(e) if e.kind() == std::io::ErrorKind::Other && e.to_string() == "stream error")
                );
            }
        };
    }

    define_test!(
        sync_headers,
        BlockHeadersRequest,
        BlockHeadersResponse,
        InboundHeadersSyncRequest,
        send_headers_sync_request,
        BadCodec::Headers
    );

    define_test!(
        sync_classes,
        ClassesRequest,
        ClassesResponse,
        InboundClassesSyncRequest,
        send_classes_sync_request,
        BadCodec::Classes
    );

    define_test!(
        sync_state_diffs,
        StateDiffsRequest,
        StateDiffsResponse,
        InboundStateDiffsSyncRequest,
        send_state_diffs_sync_request,
        BadCodec::StateDiffs
    );

    define_test!(
        sync_transactions,
        TransactionsRequest,
        TransactionsResponse,
        InboundTransactionsSyncRequest,
        send_transactions_sync_request,
        BadCodec::Transactions
    );

    define_test!(
        sync_events,
        EventsRequest,
        EventsResponse,
        InboundEventsSyncRequest,
        send_events_sync_request,
        BadCodec::Events
    );
}
