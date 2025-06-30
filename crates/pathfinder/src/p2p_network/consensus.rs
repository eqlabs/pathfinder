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
