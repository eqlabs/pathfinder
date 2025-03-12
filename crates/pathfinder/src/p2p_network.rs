use anyhow::Context;
use p2p::client::peer_agnostic;
use p2p::libp2p::identity::Keypair;
use p2p::libp2p::multiaddr::Multiaddr;
use pathfinder_common::ChainId;
use pathfinder_storage::Storage;
use tracing::Instrument;

mod sync_handlers;

use sync_handlers::{get_classes, get_events, get_headers, get_state_diffs, get_transactions};

// Silence clippy
pub type P2PNetworkHandle = (
    peer_agnostic::Client,
    tokio::task::JoinHandle<anyhow::Result<()>>,
);

pub struct P2PContext {
    pub cfg: p2p::Config,
    pub chain_id: ChainId,
    pub storage: Storage,
    pub keypair: Keypair,
    pub listen_on: Vec<Multiaddr>,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub predefined_peers: Vec<Multiaddr>,
}

#[tracing::instrument(name = "p2p", skip_all)]
pub async fn start(context: P2PContext) -> anyhow::Result<P2PNetworkHandle> {
    let P2PContext {
        cfg,
        chain_id,
        storage,
        keypair,
        listen_on,
        bootstrap_addresses,
        predefined_peers,
    } = context;

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "🖧 Starting P2P");

    let (p2p_client, mut p2p_events, p2p_main_loop) = p2p::new(keypair, cfg, chain_id);

    let mut main_loop_handle = {
        let span = tracing::info_span!("behaviour");
        util::task::spawn(p2p_main_loop.run().instrument(span))
    };

    for addr in listen_on {
        p2p_client
            .start_listening(addr.clone())
            .await
            .with_context(|| format!("Starting P2P listener: {addr}"))?;
    }

    let ensure_peer_id_in_multiaddr = |addr: &Multiaddr, msg: &'static str| {
        addr.iter()
            .find_map(|p| match p {
                p2p::libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!(msg))
    };

    for bootstrap_address in bootstrap_addresses {
        let peer_id = ensure_peer_id_in_multiaddr(
            &bootstrap_address,
            "Bootstrap addresses must include peer ID",
        )?;
        p2p_client.dial(peer_id, bootstrap_address.clone()).await?;
        p2p_client
            .start_listening(
                bootstrap_address
                    .clone()
                    .with(p2p::libp2p::multiaddr::Protocol::P2pCircuit),
            )
            .await
            .context("Starting relay listener")?;
    }

    for peer in predefined_peers {
        let peer_id = ensure_peer_id_in_multiaddr(&peer, "Predefined peers must include peer ID")?;
        p2p_client.dial(peer_id, peer).await?;
    }

    let join_handle = {
        util::task::spawn(
            async move {
                loop {
                    tokio::select! {
                        _ = &mut main_loop_handle => {
                            tracing::error!("p2p task ended unexpectedly");
                            anyhow::bail!("p2p task ended unexpectedly");
                        }
                        Some(event) = p2p_events.recv() => {
                            match handle_p2p_event(event, storage.clone()).await {
                                Ok(()) => {},
                                Err(e) => { tracing::error!("Failed to handle P2P event: {:#}", e) },
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        )
    };

    Ok((peer_agnostic::Client::new(p2p_client), join_handle))
}

async fn handle_p2p_event(event: p2p::Event, storage: Storage) -> anyhow::Result<()> {
    match event {
        p2p::Event::InboundHeadersSyncRequest {
            request, channel, ..
        } => {
            get_headers(storage, request, channel).await;
        }
        p2p::Event::InboundClassesSyncRequest {
            request, channel, ..
        } => {
            get_classes(storage, request, channel).await;
        }
        p2p::Event::InboundStateDiffsSyncRequest {
            request, channel, ..
        } => {
            get_state_diffs(storage, request, channel).await;
        }
        p2p::Event::InboundTransactionsSyncRequest {
            request, channel, ..
        } => {
            get_transactions(storage, request, channel).await;
        }
        p2p::Event::InboundEventsSyncRequest {
            request, channel, ..
        } => {
            get_events(storage, request, channel).await;
        }
        p2p::Event::SyncPeerConnected { .. } | p2p::Event::Test(_) => { /* Ignore me */ }
    }

    Ok(())
}
