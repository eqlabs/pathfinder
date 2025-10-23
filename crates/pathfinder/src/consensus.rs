use std::path::{Path, PathBuf};

use p2p::consensus::{Client, Event};
use pathfinder_common::{ChainId, ConsensusInfo};
use pathfinder_storage::Storage;
use tokio::sync::{mpsc, watch};

use crate::config::{integration_testing, ConsensusConfig};

#[cfg(feature = "p2p")]
mod inner;

pub type ConsensusP2PEventProcessingTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;
pub type ConsensusEngineTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;

pub struct ConsensusTaskHandles {
    pub consensus_p2p_event_processing_handle: ConsensusP2PEventProcessingTaskHandle,
    pub consensus_engine_handle: ConsensusEngineTaskHandle,
    pub consensus_info_watch: Option<watch::Receiver<Option<ConsensusInfo>>>,
}

impl ConsensusTaskHandles {
    pub fn pending() -> Self {
        Self {
            consensus_p2p_event_processing_handle: tokio::task::spawn(std::future::pending()),
            consensus_engine_handle: tokio::task::spawn(std::future::pending()),
            consensus_info_watch: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    config: ConsensusConfig,
    chain_id: ChainId,
    storage: Storage,
    wal_directory: PathBuf,
    p2p_client: Client,
    p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    data_directory: &Path,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure_config: integration_testing::InjectFailureConfig,
) -> ConsensusTaskHandles {
    inner::start(
        config,
        chain_id,
        storage,
        wal_directory,
        p2p_client,
        p2p_event_rx,
        data_directory,
        inject_failure_config,
    )
}

#[cfg(not(feature = "p2p"))]
mod inner {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn start(
        _: ConsensusConfig,
        _: ChainId,
        _: Storage,
        _: PathBuf,
        _: Client,
        _: mpsc::UnboundedReceiver<Event>,
        _: &Path,
        _: integration_testing::InjectFailureConfig,
    ) -> ConsensusTaskHandles {
        ConsensusTaskHandles::pending()
    }
}
