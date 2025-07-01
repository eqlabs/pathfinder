#[cfg(feature = "p2p")]
use inner::start_inner;
use pathfinder_common::ChainId;
use tokio::task::{self, JoinHandle};

use crate::config::p2p::P2PConsensusConfig;

// TODO
// Placeholder for consensus client
type Client = ();

pub async fn start(
    chain_id: ChainId,
    config: P2PConsensusConfig,
) -> (JoinHandle<anyhow::Result<()>>, Option<Client>) {
    start_inner(chain_id, config).await.unwrap_or_else(|error| {
        (
            task::spawn(std::future::ready(Err(
                error.context("Consensus P2P failed to start")
            ))),
            None,
        )
    })
}

#[cfg(feature = "p2p")]
mod inner {
    use std::time::Duration;

    use anyhow::Context;
    use p2p::consensus::Event;
    // TODO
    // use p2p::consensus::client::peer_agnostic;
    use p2p::libp2p::multiaddr::{Multiaddr, Protocol};
    use pathfinder_common::ChainId;
    use pathfinder_storage::Storage;
    use tokio::task::JoinHandle;
    use tracing::Instrument;

    use super::Client;
    use crate::config::p2p::{P2PConsensusConfig, P2PSyncConfig};
    use crate::p2p_network::identity;

    #[tracing::instrument(name = "p2p", skip_all)]
    pub(super) async fn start_inner(
        chain_id: ChainId,
        config: P2PConsensusConfig,
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
            kad_name: config.core.kad_name,
        };
        let keypair = identity::load_or_generate(config.core.identity_config_file)?;
        let listen_on = config.core.listen_on;
        let bootstrap_addresses = config.core.bootstrap_addresses;
        let predefined_peers = config.core.predefined_peers;

        let peer_id = keypair.public().to_peer_id();
        tracing::info!(%peer_id, "🖧 Starting consensus P2P");

        let (core_client, mut p2p_events, p2p_main_loop) = p2p::new_consensus(
            keypair,
            core_config,
            p2p::consensus::Config {/*TODO*/},
            chain_id,
        );

        let mut main_loop_handle = {
            let span = tracing::info_span!("behaviour");
            util::task::spawn(p2p_main_loop.run().instrument(span))
        };

        for addr in listen_on {
            core_client
                .start_listening(addr.clone())
                .await
                .with_context(|| format!("Starting consensus P2P listener: {addr}"))?;
        }

        let ensure_peer_id_in_multiaddr = |addr: &Multiaddr, msg: &'static str| {
            addr.iter()
                .find_map(|p| match p {
                    Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                })
                .ok_or_else(|| anyhow::anyhow!(msg))
        };

        for bootstrap_address in bootstrap_addresses {
            let peer_id = ensure_peer_id_in_multiaddr(
                &bootstrap_address,
                "Bootstrap addresses must include peer ID",
            )?;
            core_client.dial(peer_id, bootstrap_address.clone()).await?;
            core_client
                .start_listening(bootstrap_address.clone().with(Protocol::P2pCircuit))
                .await
                .context("Starting relay listener")?;
        }

        for peer in predefined_peers {
            let peer_id =
                ensure_peer_id_in_multiaddr(&peer, "Predefined peers must include peer ID")?;
            core_client.dial(peer_id, peer).await?;
        }

        let join_handle = {
            util::task::spawn(
                async move {
                    loop {
                        tokio::select! {
                            _ = &mut main_loop_handle => {
                                tracing::error!("consensus p2p task ended unexpectedly");
                                anyhow::bail!("consensus p2p task ended unexpectedly");
                            }
                            Some(event) = p2p_events.recv() => {
                                match handle_p2p_event(event).await {
                                    Ok(()) => {},
                                    Err(e) => { tracing::error!("Failed to handle consensus P2P event: {:#}", e) },
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
            Some(() /* Client::new(core_client.as_pair().into()) */),
        ))
    }

    async fn handle_p2p_event(event: Event) -> anyhow::Result<()> {
        match event {
            Event::Proposal(height_and_round, proposal_part) => { /*TODO*/ }
            Event::Vote(vote) => { /*TODO*/ }
        }

        Ok(())
    }
}

#[cfg(not(feature = "p2p"))]
async fn start_inner(
    _: ChainId,
    _: P2PConsensusConfig,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Option<Client>)> {
    Ok((tokio::task::spawn(futures::future::pending()), None))
}
