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
            .collect::<HashSet<_>>()
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
/// `f` should return None. This function returns a receiver to the filtered
/// events' data channel.
fn filter_events<T: Debug + Send + 'static>(
    mut event_receiver: EventReceiver,
    f: impl FnOnce(Event) -> Option<T> + Copy + Send + 'static,
) -> tokio::sync::mpsc::Receiver<T> {
    let (tx, rx) = tokio::sync::mpsc::channel(100);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = event_receiver.recv() => match event {
                    Some(event) => {
                        match f(event) {
                            Some(data) => tx.send(data).await.unwrap(),
                            None => {},
                        }
                    },
                    None => {},
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
async fn dial_succeds() {
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

// TODO figure out how to make this test run using tokio::time::pause()
#[test_log::test(tokio::test)]
async fn periodic_bootstrap() {
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
        Event::Test(TestEvent::PeriodicBootstrapCompleted) => Some(()),
        _ => None,
    };

    consume_events(boot.event_receiver);
    let mut peer1_bootstrap_done = filter_events(peer1.event_receiver, filter_periodic_bootstrap);
    let mut peer2_bootstrap_done = filter_events(peer2.event_receiver, filter_periodic_bootstrap);

    tokio::join!(
        async {
            peer1_bootstrap_done.recv().await;
            peer1_bootstrap_done.recv().await;
        },
        async {
            peer2_bootstrap_done.recv().await;
            peer2_bootstrap_done.recv().await;
        },
    );

    let boot_dht = boot.client.for_test().get_peers_from_dht().await;
    let dht1 = peer1.client.for_test().get_peers_from_dht().await;
    let dht2 = peer2.client.for_test().get_peers_from_dht().await;

    assert_eq!(
        boot_dht,
        [peer1.peer_id.clone(), peer2.peer_id.clone()].into()
    );
    assert_eq!(dht1, [boot.peer_id.clone(), peer2.peer_id.clone()].into());
    assert_eq!(dht2, [boot.peer_id.clone(), peer1.peer_id.clone()].into());
}
