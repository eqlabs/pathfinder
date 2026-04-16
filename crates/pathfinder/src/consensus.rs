use std::path::{Path, PathBuf};

use p2p::consensus::Event;
use pathfinder_common::ChainId;
use pathfinder_gas_price::L1GasPriceProvider;
use pathfinder_storage::Storage;
use pathfinder_validator::ValidatorWorkerPool;
use tokio::sync::mpsc;

use crate::config::integration_testing::InjectFailureConfig;
use crate::config::ConsensusConfig;

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

pub use crate::ConsensusChannels;

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
    gas_price_provider: Option<L1GasPriceProvider>,
    verify_tree_hashes: bool,
    compiler_resource_limits: pathfinder_compiler::ResourceLimits,
    blockifier_libfuncs: pathfinder_compiler::BlockifierLibfuncs,
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
        gas_price_provider,
        verify_tree_hashes,
        compiler_resource_limits,
        blockifier_libfuncs,
        inject_failure_config,
    )
}
