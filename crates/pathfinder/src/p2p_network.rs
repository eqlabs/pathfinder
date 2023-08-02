use std::sync::Arc;

use anyhow::Context;
use p2p::libp2p::{identity::Keypair, multiaddr::Multiaddr, PeerId};
use p2p::{HeadReceiver, HeadSender, Peers, SyncClient};
use pathfinder_common::{BlockHash, BlockNumber, ChainId};
use pathfinder_rpc::SyncState;
use pathfinder_storage::Storage;
use stark_hash::Felt;
use tokio::sync::RwLock;
use tracing::Instrument;

pub mod client;
mod sync_handlers;

// Silence clippy
pub type P2PNetworkHandle = (
    Arc<RwLock<Peers>>,
    SyncClient,
    HeadReceiver,
    tokio::task::JoinHandle<()>,
);

pub struct P2PContext {
    pub chain_id: ChainId,
    pub storage: Storage,
    pub sync_state: Arc<SyncState>,
    pub proxy: bool,
    pub keypair: Keypair,
    pub listen_on: Multiaddr,
    pub bootstrap_addresses: Vec<Multiaddr>,
}

#[tracing::instrument(name = "p2p", skip_all)]
pub async fn start(context: P2PContext) -> anyhow::Result<P2PNetworkHandle> {
    let P2PContext {
        chain_id,
        mut storage,
        sync_state,
        proxy,
        keypair,
        listen_on,
        bootstrap_addresses,
    } = context;

    let peer_id = keypair.public().to_peer_id();
    tracing::info!(%peer_id, "Starting P2P");

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

    for bootstrap_address in bootstrap_addresses {
        let peer_id = bootstrap_address
            .iter()
            .find_map(|p| match p {
                p2p::libp2p::multiaddr::Protocol::P2p(h) => PeerId::from_multihash(h).ok(),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("Boostrap addresses must inlcude peer ID"))?;
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

    let block_propagation_topic = format!("blocks/{}", chain_id.to_hex_str());

    if proxy {
        // Proxy nodes don't subscribe to topic they're publishing to
        p2p_client.subscribe_topic(&block_propagation_topic).await?;
    }

    let capabilities = ["core/block-propagate/1", "core/blocks-sync/1"];
    for capability in capabilities {
        p2p_client.provide_capability(capability).await?
    }

    let (tx, rx) = tokio::sync::watch::channel(None);
    let (tx2, mut rx2) = tokio::sync::mpsc::channel(1);

    let _jh = tokio::task::spawn(async move {
        while let Some(x) = rx2.recv().await {
            _ = tx.send(Some(x));
        }
    });

    let join_handle = {
        let mut p2p_client = p2p_client.clone();
        tokio::task::spawn(
            async move {
                loop {
                    tokio::select! {
                        _ = &mut main_loop_handle => {
                            tracing::error!("p2p task ended unexpectedly");
                            break;
                        }
                        Some(event) = p2p_events.recv() => {
                            match handle_p2p_event(event, chain_id, &mut storage, &sync_state, &mut p2p_client, tx2.clone()).await {
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
        SyncClient::new(p2p_client, block_propagation_topic, peers),
        rx,
        join_handle,
    ))
}

async fn handle_p2p_event(
    event: p2p::Event,
    chain_id: ChainId,
    storage: &mut Storage,
    sync_state: &SyncState,
    p2p_client: &mut p2p::Client,
    tx: HeadSender,
) -> anyhow::Result<()> {
    match event {
        p2p::Event::SyncPeerConnected { peer_id }
        | p2p::Event::SyncPeerRequestStatus { peer_id } => {
            // get initial status by sending a status request
            p2p_client
                .send_sync_status_request(peer_id, current_status(chain_id, sync_state).await)
                .await;
        }
        p2p::Event::InboundSyncRequest {
            request, channel, ..
        } => {
            use p2p_proto::sync::{Request, Response};
            let response = match request {
                Request::GetBlockHeaders(r) => {
                    Response::BlockHeaders(sync_handlers::get_block_headers(r, storage).await?)
                }
                Request::GetBlockBodies(r) => {
                    Response::BlockBodies(sync_handlers::get_block_bodies(r, storage).await?)
                }
                Request::GetStateDiffs(r) => {
                    Response::StateDiffs(sync_handlers::get_state_diffs(r, storage).await?)
                }
                Request::GetClasses(r) => {
                    Response::Classes(sync_handlers::get_classes(r, storage).await?)
                }
                Request::Status(_) => Response::Status(current_status(chain_id, sync_state).await),
            };
            p2p_client.send_sync_response(channel, response).await;
        }
        p2p::Event::BlockPropagation { from, message } => {
            tracing::info!(%from, ?message, "Block Propagation");
            if let p2p_proto::propagation::Message::NewBlockHeader(h) = *message {
                _ = tx
                    .send((
                        BlockNumber::new_or_panic(h.header.number),
                        BlockHash(h.header.hash),
                    ))
                    .await
            }
        }
        p2p::Event::Test(_) => { /* Ignore me */ }
    }

    Ok(())
}

async fn current_status(chain_id: ChainId, sync_state: &SyncState) -> p2p_proto::sync::Status {
    use p2p_proto::sync::Status;
    use pathfinder_rpc::v02::types::syncing::Syncing;

    let sync_status = { sync_state.status.read().await.clone() };
    match sync_status {
        Syncing::False(_) => Status {
            chain_id: chain_id.0,
            height: 0,
            hash: Felt::ZERO,
        },
        Syncing::Status(status) => Status {
            chain_id: chain_id.0,
            height: status.current.number.get(),
            hash: status.current.hash.0,
        },
    }
}
