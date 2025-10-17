#[cfg(feature = "p2p")]
mod sync_handlers;
use p2p::sync::client::peer_agnostic::Client;
use pathfinder_common::ChainId;
use pathfinder_storage::Storage;
use tokio::task::JoinHandle;

use crate::config::p2p::P2PSyncConfig;

pub async fn start(
    chain_id: ChainId,
    storage: Storage,
    config: P2PSyncConfig,
) -> (JoinHandle<anyhow::Result<()>>, Option<Client>) {
    inner::start(chain_id, storage, config)
        .await
        .unwrap_or_else(|error| {
            (
                tokio::task::spawn(std::future::ready(Err(
                    error.context("Sync P2P failed to start")
                ))),
                None,
            )
        })
}

#[cfg(feature = "p2p")]
mod inner {
    use std::time::Duration;

    use anyhow::Context;
    use p2p::libp2p::multiaddr::Protocol;
    use p2p::sync::client::peer_agnostic;
    use p2p::sync::client::peer_agnostic::Client;
    use p2p::sync::Event;
    use pathfinder_common::ChainId;
    use pathfinder_storage::Storage;
    use tokio::task::JoinHandle;
    use tracing::Instrument;

    use super::sync_handlers::{
        get_classes,
        get_events,
        get_headers,
        get_state_diffs,
        get_transactions,
    };
    use crate::config::p2p::P2PSyncConfig;
    use crate::p2p_network::common::{dial_bootnodes, ensure_peer_id_in_multiaddr};
    use crate::p2p_network::identity;

    const EVENT_CHANNEL_SIZE_LIMIT: usize = 1024;

    #[tracing::instrument(name = "p2p", skip_all)]
    pub(super) async fn start(
        chain_id: ChainId,
        storage: Storage,
        config: P2PSyncConfig,
    ) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Option<Client>)> {
        let core_config = p2p::core::Config {
            direct_connection_timeout: config.core.direct_connection_timeout,
            relay_connection_timeout: Duration::from_secs(10),
            max_inbound_direct_peers: config.core.max_inbound_direct_connections,
            max_inbound_relayed_peers: config.core.max_inbound_relayed_connections,
            max_outbound_peers: config.core.max_outbound_connections,
            ip_whitelist: config.core.ip_whitelist,
            bootstrap_period: Some(Duration::from_secs(2 * 60)),
            eviction_timeout: config.core.eviction_timeout,
            inbound_connections_rate_limit: p2p::core::config::RateLimit {
                max: 10,
                interval: Duration::from_secs(1),
            },
            max_read_bytes_per_sec: config.core.max_read_bytes_per_sec,
            max_write_bytes_per_sec: config.core.max_write_bytes_per_sec,
            kad_name: config.core.kad_name,
        };
        let sync_config = p2p::sync::Config {
            stream_timeout: config.stream_timeout,
            response_timeout: config.response_timeout,
            max_concurrent_streams: config.max_concurrent_streams,
        };
        let keypair = identity::load_or_generate(config.core.identity_config_file.clone())
            .context(format!(
                "Loading identity file: {:?}",
                config.core.identity_config_file
            ))?;
        let listen_on = config.core.listen_on;
        let bootstrap_addresses = config.core.bootstrap_addresses;
        let mut predefined_peers = config.core.predefined_peers;

        let my_peer_id = keypair.public().to_peer_id();
        tracing::info!(%my_peer_id, "🖧 Starting sync P2P");

        // In testing it is convenient to paste the entire list of peers into their
        // configs without having to remove the peer ID of the very configured peer.
        if let Some(my_idx) = predefined_peers.iter().position(|addr| {
            addr.iter()
                .any(|p| matches!(p, Protocol::P2p(peer_id) if peer_id == my_peer_id))
        }) {
            predefined_peers.swap_remove(my_idx);
        }

        let (core_client, mut p2p_events, p2p_main_loop) =
            p2p::new_sync(keypair, core_config, sync_config, chain_id);

        let mut main_loop_handle = {
            let span = tracing::info_span!("behaviour");
            util::task::spawn(p2p_main_loop.run().instrument(span))
        };

        for addr in listen_on {
            core_client
                .start_listening(addr.clone())
                .await
                .with_context(|| format!("Starting sync P2P listener: {addr}"))?;
        }

        if !dial_bootnodes(bootstrap_addresses, &core_client).await {
            anyhow::bail!("Failed to dial any configured bootstrap node")
        }

        for peer in predefined_peers {
            let peer_id =
                ensure_peer_id_in_multiaddr(&peer, "Predefined peers must include peer ID")?;
            core_client.dial(peer_id, peer).await?;
        }

        let join_handle = {
            util::task::spawn(
                async move {
                    // Keep track of whether we've already emitted a warning about the
                    // event channel size exceeding the limit, to avoid spamming the logs.
                    let mut channel_size_warning_emitted = false;

                    loop {
                        tokio::select! {
                            _ = &mut main_loop_handle => {
                                tracing::error!("sync p2p task ended unexpectedly");
                                anyhow::bail!("sync p2p task ended unexpectedly");
                            }
                            Some(event) = p2p_events.recv() => {
                                // Unbounded channel size monitoring.
                                let channel_size = p2p_events.len();
                                if channel_size > EVENT_CHANNEL_SIZE_LIMIT {
                                    if !channel_size_warning_emitted {
                                        tracing::warn!(%channel_size, "Event channel size exceeded limit");
                                        channel_size_warning_emitted = true;
                                    }
                                } else {
                                    channel_size_warning_emitted = false;
                                }

                                match handle_p2p_event(event, storage.clone()).await {
                                    Ok(()) => {},
                                    Err(e) => { tracing::error!("Failed to handle sync P2P event: {:#}", e) },
                                }
                            }
                        }
                    }
                }
                .in_current_span(),
            )
        };

        Ok((
            join_handle,
            Some(peer_agnostic::Client::new(core_client.as_pair().into())),
        ))
    }

    async fn handle_p2p_event(event: Event, storage: Storage) -> anyhow::Result<()> {
        match event {
            Event::InboundHeadersRequest {
                request, channel, ..
            } => {
                get_headers(storage, request, channel).await;
            }
            Event::InboundClassesRequest {
                request, channel, ..
            } => {
                get_classes(storage, request, channel).await;
            }
            Event::InboundStateDiffsRequest {
                request, channel, ..
            } => {
                get_state_diffs(storage, request, channel).await;
            }
            Event::InboundTransactionsRequest {
                request, channel, ..
            } => {
                get_transactions(storage, request, channel).await;
            }
            Event::InboundEventsRequest {
                request, channel, ..
            } => {
                get_events(storage, request, channel).await;
            }
        }

        Ok(())
    }
}

#[cfg(not(feature = "p2p"))]
mod inner {
    use super::*;

    pub(super) async fn start(
        _: ChainId,
        _: Storage,
        _: P2PSyncConfig,
    ) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Option<Client>)> {
        Ok((tokio::task::spawn(futures::future::pending()), None))
    }
}
