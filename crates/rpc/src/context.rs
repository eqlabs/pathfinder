use std::num::NonZeroUsize;
use std::sync::Arc;

use pathfinder_common::ChainId;
use pathfinder_executor::{TraceCache, VersionedConstants};
use pathfinder_storage::Storage;

pub use crate::jsonrpc::websocket::WebsocketContext;
use crate::jsonrpc::Notifications;
use crate::pending::{PendingData, PendingWatcher};
use crate::SyncState;

type SequencerClient = starknet_gateway_client::Client;
use tokio::sync::watch as tokio_watch;

#[derive(Clone)]
pub struct RpcConfig {
    pub batch_concurrency_limit: NonZeroUsize,
    pub get_events_max_blocks_to_scan: NonZeroUsize,
    pub get_events_max_uncached_bloom_filters_to_load: NonZeroUsize,
    pub custom_versioned_constants: Option<VersionedConstants>,
}

#[derive(Clone)]
pub struct RpcContext {
    pub cache: TraceCache,
    pub storage: Storage,
    pub execution_storage: Storage,
    pub pending_data: PendingWatcher,
    pub sync_status: Arc<SyncState>,
    pub chain_id: ChainId,
    pub sequencer: SequencerClient,
    pub websocket: Option<WebsocketContext>,
    pub notifications: Notifications,
    pub config: RpcConfig,
}

impl RpcContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Storage,
        execution_storage: Storage,
        sync_status: Arc<SyncState>,
        chain_id: ChainId,
        sequencer: SequencerClient,
        pending_data: tokio_watch::Receiver<PendingData>,
        notifications: Notifications,
        config: RpcConfig,
    ) -> Self {
        let pending_data = PendingWatcher::new(pending_data);
        Self {
            cache: Default::default(),
            storage,
            execution_storage,
            sync_status,
            chain_id,
            pending_data,
            sequencer,
            websocket: None,
            notifications,
            config,
        }
    }

    #[cfg(test)]
    pub fn for_tests() -> Self {
        Self::for_tests_on(pathfinder_common::Chain::SepoliaTestnet)
    }

    #[cfg(test)]
    pub fn for_tests_with_trie_pruning(trie_prune_mode: pathfinder_storage::TriePruneMode) -> Self {
        Self::for_tests_impl(pathfinder_common::Chain::SepoliaTestnet, trie_prune_mode)
    }

    #[cfg(test)]
    pub fn for_tests_on(chain: pathfinder_common::Chain) -> Self {
        Self::for_tests_impl(chain, pathfinder_storage::TriePruneMode::Archive)
    }

    #[cfg(test)]
    pub fn for_tests_impl(
        chain: pathfinder_common::Chain,
        trie_prune_mode: pathfinder_storage::TriePruneMode,
    ) -> Self {
        use gateway_test_utils::GATEWAY_TIMEOUT;
        use pathfinder_common::Chain;

        let (chain_id, sequencer) = match chain {
            Chain::Mainnet => (ChainId::MAINNET, SequencerClient::mainnet(GATEWAY_TIMEOUT)),
            Chain::SepoliaTestnet => (
                ChainId::SEPOLIA_TESTNET,
                SequencerClient::sepolia_testnet(GATEWAY_TIMEOUT),
            ),
            Chain::SepoliaIntegration => (
                ChainId::SEPOLIA_INTEGRATION,
                SequencerClient::sepolia_integration(GATEWAY_TIMEOUT),
            ),
            Chain::Custom => unreachable!("Should not be testing with custom chain"),
        };

        let storage = super::test_utils::setup_storage(trie_prune_mode);
        let sync_state = Arc::new(SyncState::default());
        let (_, rx) = tokio_watch::channel(Default::default());

        let config = RpcConfig {
            batch_concurrency_limit: NonZeroUsize::new(8).unwrap(),
            get_events_max_blocks_to_scan: NonZeroUsize::new(1000).unwrap(),
            get_events_max_uncached_bloom_filters_to_load: NonZeroUsize::new(1000).unwrap(),
            custom_versioned_constants: None,
        };

        Self::new(
            storage.clone(),
            storage,
            sync_state,
            chain_id,
            sequencer.disable_retry_for_tests(),
            rx,
            Notifications::default(),
            config,
        )
    }

    pub fn with_storage(self, storage: Storage) -> Self {
        Self {
            storage: storage.clone(),
            execution_storage: storage,
            ..self
        }
    }

    pub fn with_pending_data(self, pending_data: tokio_watch::Receiver<PendingData>) -> Self {
        let pending_data = PendingWatcher::new(pending_data);
        Self {
            pending_data,
            ..self
        }
    }

    #[cfg(test)]
    pub async fn for_tests_with_pending() -> Self {
        // This is a bit silly with the arc in and out, but since its for tests the
        // ergonomics of having Arc also constructed is nice.
        let context = Self::for_tests();
        let pending_data = super::test_utils::create_pending_data(context.storage.clone()).await;

        let (tx, rx) = tokio_watch::channel(Default::default());
        tx.send(pending_data).unwrap();

        context.with_pending_data(rx)
    }

    pub fn with_websockets(self, websockets: WebsocketContext) -> Self {
        Self {
            websocket: Some(websockets),
            ..self
        }
    }
}
