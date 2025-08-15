use std::path::PathBuf;

use p2p::consensus::{Client, Event};
use pathfinder_common::ChainId;
use tokio::sync::mpsc;

use crate::config::ConsensusConfig;

#[cfg(feature = "p2p")]
mod inner;

pub type ConsensusP2PEventProcessingTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;
pub type ConsensusEngineTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;

pub struct ConsensusTaskHandles {
    pub consensus_p2p_event_processing_handle: ConsensusP2PEventProcessingTaskHandle,
    pub consensus_engine_handle: ConsensusEngineTaskHandle,
}

impl ConsensusTaskHandles {
    pub fn pending() -> Self {
        Self {
            consensus_p2p_event_processing_handle: tokio::task::spawn(std::future::pending()),
            consensus_engine_handle: tokio::task::spawn(std::future::pending()),
        }
    }
}

pub fn start(
    config: ConsensusConfig,
    chain_id: ChainId,
    wal_directory: PathBuf,
    p2p_client: Client,
    p2p_event_rx: mpsc::UnboundedReceiver<Event>,
) -> ConsensusTaskHandles {
    inner::start(config, chain_id, wal_directory, p2p_client, p2p_event_rx)
}

#[cfg(not(feature = "p2p"))]
mod inner {
    use super::*;

    pub fn start(
        _: ConsensusConfig,
        _: ChainId,
        _: PathBuf,
        _: Client,
        _: mpsc::UnboundedReceiver<Event>,
    ) -> ConsensusTaskHandles {
        ConsensusTaskHandles::pending()
    }
}
