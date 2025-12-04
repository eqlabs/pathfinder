use std::path::{Path, PathBuf};

use p2p::consensus::Event;
use pathfinder_common::{ChainId, ConsensusInfo};
use pathfinder_storage::Storage;
use tokio::sync::{mpsc, watch};

use crate::config::integration_testing::InjectFailureConfig;
use crate::config::ConsensusConfig;
use crate::sync::catch_up::BlockData;

#[cfg(feature = "p2p")]
mod inner;

pub type ConsensusP2PEventProcessingTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;
pub type ConsensusEngineTaskHandle = tokio::task::JoinHandle<anyhow::Result<()>>;

pub struct ConsensusTaskHandles {
    pub consensus_p2p_event_processing_handle: ConsensusP2PEventProcessingTaskHandle,
    pub consensus_engine_handle: ConsensusEngineTaskHandle,
    pub consensus_channels: Option<ConsensusChannels>,
}

/// Various channels used to communicate with the consensus engine.
pub struct ConsensusChannels {
    /// Watcher for the latest [ConsensusInfo].
    pub consensus_info_watch: watch::Receiver<Option<ConsensusInfo>>,
    /// Watcher for the first block that the node is missing, either because it
    /// joined the network late or is lagging behind for a different reason.
    ///
    /// Intended to be used by the [catch up sync](crate::sync::catch_up) task.
    pub catch_up_rx: watch::Receiver<Option<u64>>,
    /// Messages on this channel indicate that a new block has been synced and
    /// needs to be stored in the database.
    ///
    /// Intended to be used by the [catch up sync](crate::sync::catch_up) task.
    /// This is done in order to keep all database writes in a single place.
    pub store_synced_block_tx: mpsc::Sender<BlockData>,
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
    storage: Storage,
    chain_id: ChainId,
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
        storage,
        chain_id,
        p2p_consensus_client,
        p2p_event_rx,
        wal_directory,
        data_directory,
        inject_failure_config,
        verify_tree_hashes,
    )
}

#[cfg(not(feature = "p2p"))]
mod inner {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    pub fn start(
        _: ConsensusConfig,
        _: Storage,
        _: ChainId,
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
