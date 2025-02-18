use std::num::NonZeroUsize;
use std::sync::Arc;

use pathfinder_common::{contract_address, ChainId, ContractAddress};
use pathfinder_ethereum::EthereumClient;
use pathfinder_executor::{TraceCache, VersionedConstants};
use pathfinder_storage::Storage;
use primitive_types::{H160, H256};
use util::percentage::Percentage;

pub use crate::jsonrpc::websocket::WebsocketContext;
use crate::jsonrpc::Notifications;
use crate::pending::{PendingData, PendingWatcher};
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
        eth_l2_token_address: H256,
        strk_l2_token_address: H256,
    ) -> anyhow::Result<Self> {
        let addresses = Self {
            l1_contract_address: contract_address,
            eth_l2_token_address: Self::from_token_addr(eth_l2_token_address)?,
            strk_l2_token_address: Self::from_token_addr(strk_l2_token_address)?,
        };
        Ok(addresses)
    }

    fn from_token_addr(addr: H256) -> anyhow::Result<ContractAddress> {
        use pathfinder_crypto::Felt;

        let felt = Felt::from_be_slice(addr.as_bytes())?;
        let contract_addr = ContractAddress::new(felt)
            .ok_or_else(|| anyhow::anyhow!("Cannot parse {} as token address", felt))?;
        Ok(contract_addr)
    }
}

#[derive(Clone)]
pub struct RpcConfig {
    pub batch_concurrency_limit: NonZeroUsize,
    pub get_events_max_blocks_to_scan: NonZeroUsize,
    pub get_events_max_uncached_event_filters_to_load: NonZeroUsize,
    pub fee_estimation_epsilon: Percentage,
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
    pub contract_addresses: EthContractAddresses,
    pub sequencer: SequencerClient,
    pub websocket: Option<WebsocketContext>,
    pub notifications: Notifications,
    pub ethereum: EthereumClient,
    pub config: RpcConfig,
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
        let pending_data = PendingWatcher::new(pending_data);
        Self {
            cache: Default::default(),
            storage,
            execution_storage,
            sync_status,
            chain_id,
            contract_addresses,
            pending_data,
            sequencer,
            websocket: None,
            notifications,
            ethereum,
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
        use pathfinder_ethereum::core_addr;

        let (chain_id, core_contract_address, sequencer) = match chain {
            Chain::Mainnet => (
                ChainId::MAINNET,
                core_addr::MAINNET,
                SequencerClient::mainnet(GATEWAY_TIMEOUT),
            ),
            Chain::SepoliaTestnet => (
                ChainId::SEPOLIA_TESTNET,
                core_addr::SEPOLIA_TESTNET,
                SequencerClient::sepolia_testnet(GATEWAY_TIMEOUT),
            ),
            Chain::SepoliaIntegration => (
                ChainId::SEPOLIA_INTEGRATION,
                core_addr::SEPOLIA_INTEGRATION,
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
            get_events_max_uncached_event_filters_to_load: NonZeroUsize::new(1000).unwrap(),
            fee_estimation_epsilon: Percentage::new(10),
            custom_versioned_constants: None,
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
