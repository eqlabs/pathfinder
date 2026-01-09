use std::path::{Path, PathBuf};

use p2p::consensus::Event;
use pathfinder_common::{ChainId, ConsensusInfo};
use pathfinder_storage::Storage;
use tokio::sync::{mpsc, watch};

use crate::config::integration_testing::InjectFailureConfig;
use crate::config::ConsensusConfig;
use crate::SyncMessageToConsensus;

mod error;
pub use error::{ProposalError, ProposalHandlingError};

#[cfg(feature = "p2p")]
mod inner;

#[cfg(all(
    feature = "p2p",
    feature = "consensus-integration-tests",
    debug_assertions
))]
pub use inner::ConsensusProposals;

pub type ConsensusP2PEventProcessingTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;
pub type ConsensusEngineTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;

pub struct ConsensusTaskHandles {
    pub consensus_p2p_event_processing_handle: ConsensusP2PEventProcessingTaskHandle,
    pub consensus_engine_handle: ConsensusEngineTaskHandle,
    pub consensus_channels: Option<ConsensusChannels>,
}

/// Various channels used to communicate with the consensus engine.
#[derive(Clone)]
pub struct ConsensusChannels {
    /// Watcher for the latest [ConsensusInfo].
    pub consensus_info_watch: watch::Receiver<ConsensusInfo>,
    /// Channel for the sync task to send requests to consensus.
    pub sync_to_consensus_tx: mpsc::Sender<SyncMessageToConsensus>,
}

impl ConsensusTaskHandles {
    pub fn pending() -> Self {
        Self {
            consensus_p2p_event_processing_handle: tokio::task::spawn(std::future::pending()),
            consensus_engine_handle: tokio::task::spawn(std::future::pending()),
            consensus_channels: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    config: ConsensusConfig,
    chain_id: ChainId,
    main_storage: Storage,
    p2p_consensus_client: p2p::consensus::Client,
    p2p_event_rx: mpsc::UnboundedReceiver<Event>,
    wal_directory: PathBuf,
    data_directory: &Path,
    verify_tree_hashes: bool,
    // Does nothing in production builds. Used for integration testing only.
    inject_failure_config: Option<InjectFailureConfig>,
) -> ConsensusTaskHandles {
    inner::start(
        config,
        chain_id,
        main_storage,
        p2p_consensus_client,
        p2p_event_rx,
        wal_directory,
        data_directory,
        verify_tree_hashes,
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
        _: p2p::consensus::Client,
        _: mpsc::UnboundedReceiver<Event>,
        _: PathBuf,
        _: &Path,
        _: bool,
        _: Option<InjectFailureConfig>,
    ) -> ConsensusTaskHandles {
        ConsensusTaskHandles::pending()
    }
}
