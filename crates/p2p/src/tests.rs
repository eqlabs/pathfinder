use crate::{self as p2p, Event, Peers};
use core::panic;
use libp2p::identity::{ed25519, Keypair};
use libp2p::Multiaddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[test_log::test(tokio::test)]
async fn dial_succeds() {
    static TEN_MINUTES: Duration = Duration::from_secs(600);

    let k1 = Keypair::Ed25519(ed25519::Keypair::generate());
    let peer1 = k1.public().to_peer_id();
    let peers_of1: Arc<RwLock<Peers>> = Default::default();
    let (mut client1, mut rx1, loop1) = p2p::new(k1, peers_of1.clone(), TEN_MINUTES);

    let k2 = Keypair::Ed25519(ed25519::Keypair::generate());
    let peer2 = k2.public().to_peer_id();
    let peers_of2: Arc<RwLock<Peers>> = Default::default();
    let (mut client2, _, loop2) = p2p::new(k2, peers_of2.clone(), TEN_MINUTES);

    tokio::spawn(loop1.run());
    tokio::spawn(loop2.run());

    let addr1 = Multiaddr::from_str("/ip4/127.0.0.1/tcp/0").unwrap();

    client1.start_listening(addr1).await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(1), rx1.recv())
        .await
        .unwrap()
        .unwrap();

    let addr1 = match event {
        Event::NewListenAddress(addr) => addr,
        _ => panic!("Unexpected event: {event:?}"),
    };

    client2.dial(peer1, addr1).await.unwrap();

    let peers_of1 = peers_of1
        .read()
        .await
        .connected()
        .map(Clone::clone)
        .collect::<Vec<_>>();

    let peers_of2 = peers_of2
        .read()
        .await
        .connected()
        .map(Clone::clone)
        .collect::<Vec<_>>();

    assert_eq!(peers_of1, vec![peer2]);
    assert_eq!(peers_of2, vec![peer1]);
}
