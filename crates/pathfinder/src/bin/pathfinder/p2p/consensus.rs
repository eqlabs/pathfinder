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
async fn start_inner(
    _chain_id: ChainId,
    _config: P2PConsensusConfig,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Option<Client>)> {
    /* TODO
    let context = P2PContext {
        cfg: p2p::Config {
            direct_connection_timeout: config.core.direct_connection_timeout,
            relay_connection_timeout: Duration::from_secs(10),
            max_inbound_direct_peers: config.core.max_inbound_direct_connections,
            max_inbound_relayed_peers: config.core.max_inbound_relayed_connections,
            max_outbound_peers: config.core.max_outbound_connections,
            ip_whitelist: config.core.ip_whitelist,
            bootstrap_period: Some(Duration::from_secs(2 * 60)),
            eviction_timeout: config.core.eviction_timeout,
            inbound_connections_rate_limit: p2p::RateLimit {
                max: 10,
                interval: Duration::from_secs(1),
            },
            kad_name: config.core.kad_name,
            stream_timeout: config.stream_timeout,
            response_timeout: config.response_timeout,
            max_concurrent_streams: config.max_concurrent_streams,
        },
        chain_id,
        storage,
        keypair: identity::load_or_generate(config.core.identity_config_file)?,
        listen_on: config.core.listen_on,
        bootstrap_addresses: config.core.bootstrap_addresses,
        predefined_peers: config.core.predefined_peers,
    };

    let (p2p_client, p2p_handle) = start(context).await?;
    */
    let p2p_client = ();
    let p2p_handle = tokio::task::spawn(futures::future::pending());

    Ok((p2p_handle, Some(p2p_client)))
}

#[cfg(not(feature = "p2p"))]
async fn start_inner(
    _: ChainId,
    _: P2PConsensusConfig,
) -> anyhow::Result<(JoinHandle<anyhow::Result<()>>, Option<Client>)> {
    Ok((tokio::task::spawn(futures::future::pending()), None))
}
