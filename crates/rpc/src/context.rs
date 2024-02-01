use crate::gas_price;
pub use crate::jsonrpc::websocket::WebsocketContext;
use crate::pending::PendingData;
use crate::pending::PendingWatcher;
use crate::SyncState;
use pathfinder_common::ChainId;
use pathfinder_executor::TraceCache;
use pathfinder_storage::Storage;
use std::num::NonZeroUsize;
use std::sync::Arc;

type SequencerClient = starknet_gateway_client::Client;
use tokio::sync::watch as tokio_watch;

#[derive(Clone)]
pub struct RpcConfig {
    pub batch_concurrency_limit: NonZeroUsize,
    pub get_events_max_blocks_to_scan: NonZeroUsize,
    pub get_events_max_uncached_bloom_filters_to_load: NonZeroUsize,
}

#[derive(Clone)]
pub struct RpcContext {
    pub cache: TraceCache,
    pub storage: Storage,
    pub execution_storage: Storage,
    pub pending_data: PendingWatcher,
    pub sync_status: Arc<SyncState>,
    pub chain_id: ChainId,
    pub eth_gas_price: gas_price::Cached,
    pub sequencer: SequencerClient,
    pub websocket: Option<WebsocketContext>,
    pub config: RpcConfig,
}

impl RpcContext {
    pub fn new(
        storage: Storage,
        execution_storage: Storage,
        sync_status: Arc<SyncState>,
        chain_id: ChainId,
        sequencer: SequencerClient,
        pending_data: tokio_watch::Receiver<PendingData>,
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
            eth_gas_price: gas_price::Cached::new(sequencer.clone()),
            sequencer,
            websocket: None,
            config,
        }
    }

    pub fn for_tests() -> Self {
        Self::for_tests_on(pathfinder_common::Chain::GoerliTestnet)
    }

    pub fn for_tests_on(chain: pathfinder_common::Chain) -> Self {
        use pathfinder_common::Chain;
        let (chain_id, sequencer) = match chain {
            Chain::Mainnet => (ChainId::MAINNET, SequencerClient::mainnet()),
            Chain::GoerliTestnet => (ChainId::GOERLI_TESTNET, SequencerClient::goerli_testnet()),
            Chain::GoerliIntegration => (
                ChainId::GOERLI_INTEGRATION,
                SequencerClient::goerli_integration(),
            ),
            Chain::SepoliaTestnet => (ChainId::SEPOLIA_TESTNET, SequencerClient::sepolia_testnet()),
            Chain::SepoliaIntegration => (
                ChainId::SEPOLIA_INTEGRATION,
                SequencerClient::sepolia_integration(),
            ),
            Chain::Custom => unreachable!("Should not be testing with custom chain"),
        };

        let storage = super::test_utils::setup_storage();
        let sync_state = Arc::new(SyncState::default());
        let (_, rx) = tokio_watch::channel(Default::default());

        let config = RpcConfig {
            batch_concurrency_limit: NonZeroUsize::new(8).unwrap(),
            get_events_max_blocks_to_scan: NonZeroUsize::new(1000).unwrap(),
            get_events_max_uncached_bloom_filters_to_load: NonZeroUsize::new(1000).unwrap(),
        };

        Self::new(
            storage.clone(),
            storage,
            sync_state,
            chain_id,
            sequencer.disable_retry_for_tests(),
            rx,
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

    pub async fn for_tests_with_pending() -> Self {
        // This is a bit silly with the arc in and out, but since its for tests the ergonomics of
        // having Arc also constructed is nice.
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
