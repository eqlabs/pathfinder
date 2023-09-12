use crate::gas_price;
use crate::websocket::types::WebsocketSenders;
use crate::SyncState;
use pathfinder_common::ChainId;
use pathfinder_storage::Storage;
use starknet_gateway_types::pending::PendingData;
use std::sync::Arc;

type SequencerClient = starknet_gateway_client::Client;

#[derive(Clone)]
pub struct RpcContext {
    pub storage: Storage,
    pub execution_storage: Storage,
    pub pending_data: Option<PendingData>,
    pub sync_status: Arc<SyncState>,
    pub chain_id: ChainId,
    pub eth_gas_price: gas_price::Cached,
    pub sequencer: SequencerClient,
    pub websocket: WebsocketSenders,
}

impl RpcContext {
    pub fn new(
        storage: Storage,
        execution_storage: Storage,
        sync_status: Arc<SyncState>,
        chain_id: ChainId,
        sequencer: SequencerClient,
    ) -> Self {
        Self {
            storage,
            execution_storage,
            sync_status,
            chain_id,
            pending_data: None,
            eth_gas_price: gas_price::Cached::new(sequencer.clone()),
            sequencer,
            websocket: WebsocketSenders::with_capacity(1),
        }
    }

    pub fn for_tests() -> Self {
        Self::for_tests_on(pathfinder_common::Chain::Testnet)
    }

    pub fn for_tests_on(chain: pathfinder_common::Chain) -> Self {
        use pathfinder_common::Chain;
        let (chain_id, sequencer) = match chain {
            Chain::Mainnet => (ChainId::MAINNET, SequencerClient::mainnet()),
            Chain::Testnet => (ChainId::TESTNET, SequencerClient::testnet()),
            Chain::Integration => (ChainId::INTEGRATION, SequencerClient::integration()),
            Chain::Testnet2 => (ChainId::TESTNET2, SequencerClient::testnet2()),
            Chain::Custom => unreachable!("Should not be testing with custom chain"),
        };

        let storage = super::test_utils::setup_storage();
        let sync_state = Arc::new(SyncState::default());
        Self::new(
            storage.clone(),
            storage,
            sync_state,
            chain_id,
            sequencer.disable_retry_for_tests(),
        )
    }

    pub fn with_storage(self, storage: Storage) -> Self {
        Self {
            storage: storage.clone(),
            execution_storage: storage,
            ..self
        }
    }

    pub fn with_pending_data(self, pending_data: PendingData) -> Self {
        Self {
            pending_data: Some(pending_data),
            ..self
        }
    }

    pub async fn for_tests_with_pending() -> Self {
        // This is a bit silly with the arc in and out, but since its for tests the ergonomics of
        // having Arc also constructed is nice.
        let context = Self::for_tests();
        let pending_data = super::test_utils::create_pending_data(context.storage.clone()).await;
        context.with_pending_data(pending_data)
    }

    pub fn with_websocket(self, websocket: WebsocketSenders) -> Self {
        Self { websocket, ..self }
    }
}
