use std::path::{Path, PathBuf};

use p2p::consensus::Event;
use pathfinder_common::{consensus_info, ChainId};
use pathfinder_storage::Storage;
use tokio::sync::{mpsc, watch};

use crate::config::integration_testing::InjectFailureConfig;
use crate::config::ConsensusConfig;
use crate::gas_price::L1GasPriceProvider;
use crate::validator::ValidatorWorkerPool;
use crate::SyncMessageToConsensus;

mod error;
pub use error::{ProposalError, ProposalHandlingError};

#[cfg(feature = "p2p")]
mod inner;

pub type ConsensusP2PEventProcessingTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;
pub type ConsensusEngineTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;

pub struct ConsensusTaskHandles {
    pub consensus_p2p_event_processing_handle: ConsensusP2PEventProcessingTaskHandle,
    pub consensus_engine_handle: ConsensusEngineTaskHandle,
    pub consensus_channels: Option<ConsensusChannels>,
    // Use to `join()` the worker pool, so that it's threads don't panic when the `p2p_task` is
    // cancelled.
    pub worker_pool: Option<ValidatorWorkerPool>,
}

/// Various channels used to communicate with the consensus engine.
#[derive(Clone)]
pub struct ConsensusChannels {
    /// Watcher for the latest [consensus_info::ConsensusInfo].
    pub consensus_info_watch: watch::Receiver<consensus_info::ConsensusInfo>,
    /// Channel for the sync task to send requests to consensus.
    pub sync_to_consensus_tx: mpsc::Sender<SyncMessageToConsensus>,
}

impl ConsensusTaskHandles {
    pub fn pending() -> Self {
        Self {
            consensus_p2p_event_processing_handle: tokio::task::spawn(std::future::pending()),
            consensus_engine_handle: tokio::task::spawn(std::future::pending()),
            consensus_channels: None,
            worker_pool: None,
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
    gas_price_provider: Option<L1GasPriceProvider>,
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
        gas_price_provider,
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
        _: Option<L1GasPriceProvider>,
        _: Option<InjectFailureConfig>,
    ) -> ConsensusTaskHandles {
        ConsensusTaskHandles::pending()
    }
}
