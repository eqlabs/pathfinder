use std::time::Duration;

use futures::future::join;
use libp2p::identity::Keypair;
use libp2p::multiaddr::Protocol;

use super::TestEvent;
use crate::core::config::RateLimit;
use crate::core::Config;
use crate::test_utils::peer::TestPeer;
use crate::test_utils::{consume_accumulated_events, consume_all_events_forever, wait_for_event};

#[test_log::test(tokio::test)]
async fn dial() {
    // tokio::time::pause() does not make a difference
    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    consume_accumulated_events(&mut peer1.test_event_receiver).await;

    let peers_of1: Vec<_> = peer1.connected().await.into_keys().collect();
    let peers_of2: Vec<_> = peer2.connected().await.into_keys().collect();

    assert_eq!(peers_of1, vec![peer2.peer_id]);
    assert_eq!(peers_of2, vec![peer1.peer_id]);
}

#[test_log::test(tokio::test)]
async fn disconnect() {
    let mut peer1 = TestPeer::default();
    let mut peer2 = TestPeer::default();

    let addr2 = peer2.start_listening().await.unwrap();
    tracing::info!(%peer2.peer_id, %addr2);

    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    consume_accumulated_events(&mut peer1.test_event_receiver).await;

    let peers_of1: Vec<_> = peer1.connected().await.into_keys().collect();
    let peers_of2: Vec<_> = peer2.connected().await.into_keys().collect();

    assert_eq!(peers_of1, vec![peer2.peer_id]);
    assert_eq!(peers_of2, vec![peer1.peer_id]);

    peer2.client.disconnect(peer1.peer_id).await.unwrap();

    wait_for_event(&mut peer1.test_event_receiver, move |event| match event {
        TestEvent::ConnectionClosed { remote } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.test_event_receiver, move |event| match event {
        TestEvent::ConnectionClosed { remote } if remote == peer1.peer_id => Some(()),
        _ => None,
    })
    .await;

    assert!(peer1.connected().await.is_empty());
    assert!(peer2.connected().await.is_empty());
}

#[test_log::test(tokio::test)]
async fn periodic_bootstrap() {
    const BOOTSTRAP_PERIOD: Duration = Duration::from_millis(500);
    let cfg = Config {
        bootstrap_period: Some(BOOTSTRAP_PERIOD),
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
        TestEvent::KademliaBootstrapCompleted(_) => Some(()),
        _ => None,
    };

    consume_all_events_forever(boot.test_event_receiver);

    let peer_id2 = peer2.peer_id;

    let peer2_added_to_dht_of_peer1 =
        wait_for_event(&mut peer1.test_event_receiver, move |event| match event {
            TestEvent::PeerAddedToDHT { remote } if remote == peer_id2 => Some(()),
            _ => None,
        });

    join(peer2_added_to_dht_of_peer1, async {
        wait_for_event(
            &mut peer2.test_event_receiver,
            filter_kademlia_bootstrap_completed,
        )
        .await;
        wait_for_event(
            &mut peer2.test_event_receiver,
            filter_kademlia_bootstrap_completed,
        )
        .await;
    })
    .await;

    consume_all_events_forever(peer1.test_event_receiver);

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

    wait_for_event(&mut peer1.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer1.peer_id => Some(()),
        _ => None,
    })
    .await;

    let peers_of1: Vec<_> = peer1.connected().await.into_keys().collect();
    let peers_of2: Vec<_> = peer2.connected().await.into_keys().collect();

    assert_eq!(peers_of1, vec![peer2.peer_id]);
    assert_eq!(peers_of2, vec![peer1.peer_id]);

    // Close the connection.
    peer1.client.disconnect(peer2.peer_id).await.unwrap();

    wait_for_event(&mut peer1.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote } if remote == peer1.peer_id => Some(()),
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
    wait_for_event(&mut peer1.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer1.peer_id => Some(()),
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

    wait_for_event(&mut peer1.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer2.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer1.peer_id => Some(()),
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

    wait_for_event(&mut peer1_copy.test_event_receiver, |event| match event {
        TestEvent::ConnectionEstablished { remote, .. } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    wait_for_event(&mut peer1_copy.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote, .. } if remote == peer2.peer_id => Some(()),
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

    consume_all_events_forever(outbound1.test_event_receiver);
    consume_all_events_forever(outbound2.test_event_receiver);
    consume_all_events_forever(outbound3.test_event_receiver);
    consume_all_events_forever(outbound4.test_event_receiver);
    consume_all_events_forever(inbound1.test_event_receiver);

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

    consume_accumulated_events(&mut peer.test_event_receiver).await;

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
    wait_for_event(&mut peer.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote, .. } if remote == outbound1.peer_id => Some(()),
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

    let mut peer = TestPeer::builder().disable_kademlia().build(cfg.clone());
    let inbound_peers = (0..26)
        .map(|_| TestPeer::builder().disable_kademlia().build(cfg.clone()))
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

    consume_accumulated_events(&mut peer.test_event_receiver).await;

    // Trying to open another one causes an eviction.
    inbound_peers
        .last()
        .unwrap()
        .client
        .dial(peer.peer_id, peer_addr.clone())
        .await
        .unwrap();

    // Ensure that a peer got disconnected.
    let disconnected = wait_for_event(&mut peer.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote, .. }
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
#[test_log::test(tokio::test)]
async fn evicted_peer_reconnection() {
    let cfg = Config {
        max_inbound_direct_peers: 10,
        max_inbound_relayed_peers: 0,
        max_outbound_peers: 1,
        bootstrap_period: None,
        ..Config::for_test()
    };

    let mut peer1 = TestPeer::builder().disable_kademlia().build(cfg.clone());
    let mut peer2 = TestPeer::builder().disable_kademlia().build(cfg.clone());
    let mut peer3 = TestPeer::builder().disable_kademlia().build(cfg.clone());

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
    wait_for_event(&mut peer1.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote, .. } if remote == peer2.peer_id => Some(()),
        _ => None,
    })
    .await;

    // Mark peer3 as not useful, and hence a candidate for eviction.
    peer1.client.not_useful(peer3.peer_id).await;

    // Try to reconnect too quickly.
    let result = peer1.client.dial(peer2.peer_id, addr2.clone()).await;
    assert!(result.is_err());

    consume_accumulated_events(&mut peer2.test_event_receiver).await;

    // In this case there is no peer ID when connecting, so the connection gets
    // closed after being established.
    peer2
        .client
        .dial(peer1.peer_id, addr1.clone())
        .await
        .unwrap();
    wait_for_event(&mut peer2.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote, .. } if remote == peer1.peer_id => Some(()),
        _ => None,
    })
    .await;

    // peer2 can be reconnected after a timeout.
    tokio::time::sleep(Duration::from_millis(500)).await;
    peer1.client.dial(peer2.peer_id, addr2).await.unwrap();

    // peer3 gets evicted.
    wait_for_event(&mut peer1.test_event_receiver, |event| match event {
        TestEvent::ConnectionClosed { remote, .. } if remote == peer3.peer_id => Some(()),
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

    consume_all_events_forever(peer2.test_event_receiver);

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

    consume_all_events_forever(peer1.test_event_receiver);
    consume_all_events_forever(peer2.test_event_receiver);
    consume_all_events_forever(peer3.test_event_receiver);
    consume_all_events_forever(peer4.test_event_receiver);

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
