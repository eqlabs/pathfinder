use crate::cairo::ext_py;
use crate::gas_price;
use crate::SyncState;
use anyhow::{Context, Ok};
use pathfinder_common::pending::PendingData;
use pathfinder_common::{BlockWithBody, ChainId, StateUpdate};
use pathfinder_storage::Storage;

use std::sync::Arc;

type SequencerClient = starknet_gateway_client::Client;

#[derive(Copy, Clone, Default)]
pub enum RpcVersion {
    #[default]
    Undefined,
    V01,
    V02,
    V03,
}

impl RpcVersion {
    fn parse(s: &str) -> Self {
        match s {
            "v0.1" => Self::V01,
            "v0.2" => Self::V02,
            "v0.3" => Self::V03,
            _ => Self::default(),
        }
    }
}

#[derive(Clone)]
pub struct RpcContext {
    pub storage: Storage,
    pub pending_data: PendingData,
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
            pending_data: Default::default(),
            call_handle: None,
            eth_gas_price: None,
            sequencer,
            version: RpcVersion::default(),
        }
    }

    pub(crate) fn pending_block(
        &self,
        db: &pathfinder_storage::Transaction<'_>,
    ) -> anyhow::Result<Option<Arc<BlockWithBody>>> {
        let Some(latest) = db
            .block_id(pathfinder_storage::BlockId::Latest)
            .context("Querying latest block hash")? else {
                return Ok(None);
            };

        Ok(self.pending_data.block(latest.1))
    }

    pub(crate) fn pending_state_update(
        &self,
        db: &pathfinder_storage::Transaction<'_>,
    ) -> anyhow::Result<Option<Arc<StateUpdate>>> {
        let Some(latest) = db
            .block_header(pathfinder_storage::BlockId::Latest)
            .context("Querying latest block header")? else {
                return Ok(None);
            };

        Ok(self.pending_data.state_update(latest.state_commitment))
    }

    pub(crate) fn with_version(self, version: &str) -> Self {
        Self {
            version: RpcVersion::parse(version),
            ..self
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_tests() -> Self {
        Self::for_tests_on(pathfinder_common::Chain::Testnet)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn for_tests_on(chain: pathfinder_common::Chain) -> Self {
        assert_ne!(chain, Chain::Mainnet, "Testing on MainNet?");

        use pathfinder_common::Chain;
        let chain_id = match chain {
            Chain::Mainnet => ChainId::MAINNET,
            Chain::Testnet => ChainId::TESTNET,
            Chain::Integration => ChainId::INTEGRATION,
            Chain::Testnet2 => ChainId::TESTNET2,
            Chain::Custom => unreachable!("Should not be testing with custom chain"),
        };

        let storage = super::test_utils::setup_storage();
        let sync_state = Arc::new(SyncState::default());
        let sequencer = SequencerClient::new(chain).unwrap();
        Self::new(storage, sync_state, chain_id, sequencer)
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub fn with_storage(self, storage: Storage) -> Self {
        Self { storage, ..self }
    }

    pub fn with_pending_data(self, pending_data: PendingData) -> Self {
        Self {
            pending_data,
            ..self
        }
    }

    #[cfg(any(test, feature = "test-utils"))]
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
