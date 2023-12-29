use std::sync::Arc;

use anyhow::Context;
use p2p::client::peer_agnostic;
use p2p::libp2p::{identity::Keypair, multiaddr::Multiaddr};
use p2p::{HeadRx, HeadTx, Peers};
use pathfinder_common::{BlockHash, BlockNumber, ChainId};
use pathfinder_storage::Storage;
use tokio::sync::RwLock;
use tracing::Instrument;

pub mod client;
mod sync_handlers;

use sync_handlers::{get_bodies, get_events, get_headers, get_receipts, get_transactions};

// Silence clippy
pub type P2PNetworkHandle = (
    Arc<RwLock<Peers>>,
    peer_agnostic::Client,
    HeadRx,
    tokio::task::JoinHandle<()>,
);

pub struct P2PContext {
    pub chain_id: ChainId,
    pub storage: Storage,
    pub proxy: bool,
    pub keypair: Keypair,
    pub listen_on: Multiaddr,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub predefined_peers: Vec<Multiaddr>,
}

#[tracing::instrument(name = "p2p", skip_all)]
pub async fn start(context: P2PContext) -> anyhow::Result<P2PNetworkHandle> {
    let P2PContext {
        chain_id,
        storage,
        proxy,
        keypair,
        listen_on,
        bootstrap_addresses,
        predefined_peers,
    } = context;

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "🖧 Starting P2P");

    let peers: Arc<RwLock<Peers>> = Arc::new(RwLock::new(Default::default()));
    let (p2p_client, mut p2p_events, p2p_main_loop) =
        p2p::new(keypair, peers.clone(), Default::default());

    let mut main_loop_handle = {
        let span = tracing::info_span!("behaviour");
        tokio::task::spawn(p2p_main_loop.run().instrument(span))
    };

    p2p_client
        .start_listening(listen_on)
        .await
        .context("Starting P2P listener")?;

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

    let block_propagation_topic = format!("blocks/{}", chain_id.to_hex_str());

    if !proxy {
        p2p_client.subscribe_topic(&block_propagation_topic).await?;
        tracing::info!(topic=%block_propagation_topic, "Subscribed to");
    }

    for capability in p2p::PROTOCOLS {
        p2p_client.provide_capability(capability).await?
    }

    let (mut tx, rx) = tokio::sync::watch::channel(None);

    let join_handle = {
        tokio::task::spawn(
            async move {
                loop {
                    tokio::select! {
                        _ = &mut main_loop_handle => {
                            tracing::error!("p2p task ended unexpectedly");
                            break;
                        }
                        Some(event) = p2p_events.recv() => {
                            match handle_p2p_event(event, storage.clone(), &mut tx).await {
                                Ok(()) => {},
                                Err(e) => { tracing::error!("Failed to handle P2P event: {}", e) },
                            }
                        }
                    }
                }
            }
            .in_current_span(),
        )
    };

    Ok((
        peers.clone(),
        peer_agnostic::Client::new(p2p_client, block_propagation_topic, peers),
        rx,
        join_handle,
    ))
}

async fn handle_p2p_event(
    event: p2p::Event,
    storage: Storage,
    tx: &mut HeadTx,
) -> anyhow::Result<()> {
    match event {
        p2p::Event::InboundHeadersSyncRequest {
            request, channel, ..
        } => {
            get_headers(storage, request, channel).await?;
        }
        p2p::Event::InboundBodiesSyncRequest {
            request, channel, ..
        } => {
            get_bodies(storage, request, channel).await?;
        }
        p2p::Event::InboundTransactionsSyncRequest {
            request, channel, ..
        } => {
            get_transactions(storage, request, channel).await?;
        }
        p2p::Event::InboundReceiptsSyncRequest {
            request, channel, ..
        } => {
            get_receipts(storage, request, channel).await?;
        }
        p2p::Event::InboundEventsSyncRequest {
            request, channel, ..
        } => {
            get_events(storage, request, channel).await?;
        }
        p2p::Event::BlockPropagation { from, new_block } => {
            tracing::info!(%from, ?new_block, "Block Propagation");
            use p2p_proto::block::NewBlock;

            let id = match new_block {
                NewBlock::Id(id) => Some(id),
                NewBlock::Header(h) => h.parts.first().and_then(|part| part.id()),
                NewBlock::Body(b) => b.id,
            };
            let new_head =
                id.and_then(|id| BlockNumber::new(id.number).map(|n| (n, BlockHash(id.hash.0))));
            match new_head {
                Some((new_height, new_hash)) => {
                    tx.send_if_modified(|head| -> bool {
                        let current_height = head.unwrap_or_default().0;

                        if new_height > current_height {
                            *head = Some((new_height, new_hash));
                            true
                        } else {
                            false
                        }
                    });
                }
                None => {
                    tracing::warn!("Received block propagation without a valid head: {id:?}")
                }
            }
        }
        p2p::Event::SyncPeerConnected { .. } | p2p::Event::Test(_) => { /* Ignore me */ }
    }

    Ok(())
}
