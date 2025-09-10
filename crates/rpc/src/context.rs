use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;

use pathfinder_common::{contract_address, ChainId, ConsensusInfo, ContractAddress};
use pathfinder_ethereum::EthereumClient;
use pathfinder_executor::{NativeClassCache, TraceCache, VersionedConstantsMap};
use pathfinder_storage::Storage;
use primitive_types::H160;
use tokio::sync::watch;
use util::percentage::Percentage;

pub use crate::jsonrpc::websocket::WebsocketContext;
use crate::jsonrpc::Notifications;
use crate::pending::{PendingData, PendingWatcher};
use crate::tracker::SubmittedTransactionTracker;
use crate::SyncState;

type SequencerClient = starknet_gateway_client::Client;
use tokio::sync::watch as tokio_watch;

// NOTE: these are the same for all _non-custom_ networks
pub const ETH_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7");
pub const STRK_FEE_TOKEN_ADDRESS: ContractAddress =
    contract_address!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

/// Addresses from get_contract_addresses.
#[derive(Debug, Copy, Clone)]
pub struct EthContractAddresses {
    pub l1_contract_address: H160,

    pub eth_l2_token_address: ContractAddress,

    pub strk_l2_token_address: ContractAddress,
}

impl EthContractAddresses {
    pub fn new_known(contract_address: [u8; 20]) -> Self {
        Self {
            l1_contract_address: H160::from(contract_address),
            eth_l2_token_address: ETH_FEE_TOKEN_ADDRESS,
            strk_l2_token_address: STRK_FEE_TOKEN_ADDRESS,
        }
    }

    pub fn new_custom(
        contract_address: H160,
        eth_l2_token_address: Option<ContractAddress>,
        strk_l2_token_address: Option<ContractAddress>,
    ) -> Self {
        let eth_l2_token_address = eth_l2_token_address.unwrap_or_else(|| {
            tracing::warn!("ETH address unspecified, using default");
            ETH_FEE_TOKEN_ADDRESS
        });
        let strk_l2_token_address = strk_l2_token_address.unwrap_or_else(|| {
            tracing::warn!("STRK address unspecified, using default");
            STRK_FEE_TOKEN_ADDRESS
        });
        Self {
            l1_contract_address: contract_address,
            eth_l2_token_address,
            strk_l2_token_address,
        }
    }
}

#[derive(Clone)]
pub struct RpcConfig {
    pub batch_concurrency_limit: NonZeroUsize,
    pub disable_batch_requests: bool,
    pub get_events_event_filter_block_range_limit: NonZeroUsize,
    pub fee_estimation_epsilon: Percentage,
    pub versioned_constants_map: VersionedConstantsMap,
    pub native_execution: bool,
    pub native_class_cache_size: NonZeroUsize,
    pub submission_tracker_time_limit: NonZeroU64,
    pub submission_tracker_size_limit: NonZeroUsize,
}

#[derive(Clone)]
pub struct RpcContext {
    pub cache: TraceCache,
    pub storage: Storage,
    pub execution_storage: Storage,
    pub pending_data: PendingWatcher,
    pub sync_status: Arc<SyncState>,
    pub submission_tracker: SubmittedTransactionTracker,
    pub chain_id: ChainId,
    pub contract_addresses: EthContractAddresses,
    pub sequencer: SequencerClient,
    pub websocket: Option<WebsocketContext>,
    pub notifications: Notifications,
    pub ethereum: EthereumClient,
    pub config: RpcConfig,
    pub native_class_cache: Option<NativeClassCache>,
    pub consensus_info_watch: Option<watch::Receiver<Option<ConsensusInfo>>>,
}

impl RpcContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Storage,
        execution_storage: Storage,
        sync_status: Arc<SyncState>,
        chain_id: ChainId,
        contract_addresses: EthContractAddresses,
        sequencer: SequencerClient,
        pending_data: tokio_watch::Receiver<PendingData>,
        notifications: Notifications,
        ethereum: EthereumClient,
        config: RpcConfig,
    ) -> Self {
        let submission_tracker = SubmittedTransactionTracker::new(
            config.submission_tracker_size_limit.into(),
            config.submission_tracker_time_limit.into(),
        );
        let pending_watcher = PendingWatcher::new(pending_data.clone());
        let native_class_cache = if config.native_execution {
            Some(NativeClassCache::spawn(config.native_class_cache_size))
        } else {
            None
        };
        Self {
            cache: Default::default(),
            storage,
            execution_storage,
            sync_status,
            submission_tracker,
            chain_id,
            contract_addresses,
            pending_data: pending_watcher,
            sequencer,
            websocket: None,
            notifications,
            ethereum,
            config,
            native_class_cache,
            consensus_info_watch: None,
        }
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

    pub fn with_websockets(self, websockets: WebsocketContext) -> Self {
        Self {
            websocket: Some(websockets),
            ..self
        }
    }

    pub fn with_consensus_info_watch(
        self,
        consensus_info_watch: watch::Receiver<Option<ConsensusInfo>>,
    ) -> Self {
        Self {
            consensus_info_watch: Some(consensus_info_watch),
            ..self
        }
    }

    #[cfg(test)]
    pub fn with_notifications(self, notifications: Notifications) -> Self {
        Self {
            notifications,
            ..self
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
    fn for_tests_impl(
        chain: pathfinder_common::Chain,
        trie_prune_mode: pathfinder_storage::TriePruneMode,
    ) -> Self {
        use std::time::Duration;

        use pathfinder_common::Chain;
        use pathfinder_ethereum::core_addr;

        const TIMEOUT: Duration = Duration::from_secs(5);

        let (chain_id, core_contract_address, sequencer) = match chain {
            Chain::Mainnet => (
                ChainId::MAINNET,
                core_addr::MAINNET,
                SequencerClient::mainnet(TIMEOUT),
            ),
            Chain::SepoliaTestnet => (
                ChainId::SEPOLIA_TESTNET,
                core_addr::SEPOLIA_TESTNET,
                SequencerClient::sepolia_testnet(TIMEOUT),
            ),
            Chain::SepoliaIntegration => (
                ChainId::SEPOLIA_INTEGRATION,
                core_addr::SEPOLIA_INTEGRATION,
                SequencerClient::sepolia_integration(TIMEOUT),
            ),
            Chain::Custom => unreachable!("Should not be testing with custom chain"),
        };

        let storage = super::test_utils::setup_storage(trie_prune_mode);
        let sync_state = Arc::new(SyncState::default());
        let (_, rx) = tokio_watch::channel(Default::default());

        let config = RpcConfig {
            batch_concurrency_limit: NonZeroUsize::new(8).unwrap(),
            disable_batch_requests: false,
            get_events_event_filter_block_range_limit: NonZeroUsize::new(1000).unwrap(),
            fee_estimation_epsilon: Percentage::new(10),
            versioned_constants_map: Default::default(),
            native_execution: true,
            native_class_cache_size: NonZeroUsize::new(10).unwrap(),
            submission_tracker_time_limit: NonZeroU64::new(300).unwrap(),
            submission_tracker_size_limit: NonZeroUsize::new(30000).unwrap(),
        };

        let ethereum =
            EthereumClient::new("wss://eth-sepolia.g.alchemy.com/v2/just-for-tests").unwrap();

        Self::new(
            storage.clone(),
            storage,
            sync_state,
            chain_id,
            EthContractAddresses::new_known(core_contract_address),
            sequencer.disable_retry_for_tests(),
            rx,
            Notifications::default(),
            ethereum,
            config,
        )
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

    #[cfg(test)]
    pub async fn for_tests_with_pre_confirmed() -> Self {
        // This is a bit silly with the arc in and out, but since its for tests the
        // ergonomics of having Arc also constructed is nice.
        let context = Self::for_tests();
        let pending_data =
            super::test_utils::create_pre_confirmed_data(context.storage.clone()).await;

        let (tx, rx) = tokio_watch::channel(Default::default());
        tx.send(pending_data).unwrap();

        context.with_pending_data(rx)
    }

    #[cfg(test)]
    pub async fn for_tests_with_pre_latest_and_pre_confirmed() -> Self {
        let context = Self::for_tests();
        let pending_data =
            super::test_utils::create_pre_confirmed_data_with_pre_latest(context.storage.clone())
                .await;

        let (tx, rx) = tokio_watch::channel(Default::default());
        tx.send(pending_data).unwrap();

        context.with_pending_data(rx)
    }
}
