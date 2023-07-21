use crate::cairo::ext_py;
use crate::gas_price;
use crate::SyncState;
use pathfinder_common::ChainId;
use pathfinder_storage::Storage;
use starknet_gateway_types::pending::PendingData;
use std::sync::Arc;

type SequencerClient = starknet_gateway_client::Client;

#[derive(Copy, Clone, Default)]
pub enum RpcVersion {
    #[default]
    Undefined,
    V01,
    V02,
    V03,
    V04,
}

impl RpcVersion {
    fn parse(s: &str) -> Self {
        match s {
            "v0.1" => Self::V01,
            "v0.2" => Self::V02,
            "v0.3" => Self::V03,
            "v0.4" => Self::V04,
            _ => Self::default(),
        }
    }
}

#[derive(Clone)]
pub struct RpcContext {
    pub storage: Storage,
    pub pending_data: Option<PendingData>,
    pub sync_status: Arc<SyncState>,
    pub chain_id: ChainId,
    pub call_handle: Option<ext_py::Handle>,
    pub eth_gas_price: Option<gas_price::Cached>,
    pub sequencer: SequencerClient,
    pub version: RpcVersion,
}

impl RpcContext {
    pub fn new(
        storage: Storage,
        sync_status: Arc<SyncState>,
        chain_id: ChainId,
        sequencer: SequencerClient,
    ) -> Self {
        Self {
            storage,
            sync_status,
            chain_id,
            pending_data: None,
            call_handle: None,
            eth_gas_price: None,
            sequencer,
            version: RpcVersion::default(),
        }
    }

    pub(crate) fn with_version(self, version: &str) -> Self {
        Self {
            version: RpcVersion::parse(version),
            ..self
        }
    }

    pub fn for_tests() -> Self {
        Self::for_tests_on(pathfinder_common::Chain::Testnet)
    }

    pub fn for_tests_on(chain: pathfinder_common::Chain) -> Self {
        assert_ne!(chain, Chain::Mainnet, "Testing on MainNet?");

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
            storage,
            sync_state,
            chain_id,
            sequencer.disable_retry_for_tests(),
        )
    }

    pub fn with_storage(self, storage: Storage) -> Self {
        Self { storage, ..self }
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

    pub fn with_call_handling(self, call_handle: ext_py::Handle) -> Self {
        Self {
            call_handle: Some(call_handle),
            ..self
        }
    }

    pub fn with_eth_gas_price(self, gas_price: gas_price::Cached) -> Self {
        Self {
            eth_gas_price: Some(gas_price),
            ..self
        }
    }
}
