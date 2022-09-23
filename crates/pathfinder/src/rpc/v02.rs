use std::sync::Arc;

use crate::state::SyncState;
use crate::{state::PendingData, storage::Storage};

pub mod method;
pub mod types;

#[derive(Clone)]
pub struct RpcContext {
    pub storage: Storage,
    pub pending_data: Option<PendingData>,
    pub sync_status: Arc<SyncState>,
}

impl RpcContext {
    pub fn new(storage: Storage, sync_status: Arc<SyncState>) -> Self {
        Self {
            storage,
            sync_status,
            pending_data: None,
        }
    }

    #[cfg(test)]
    pub fn for_tests() -> Arc<Self> {
        let storage = super::tests::setup_storage();
        let sync_state = Arc::new(SyncState::default());
        Arc::new(Self::new(storage, sync_state))
    }

    pub fn with_pending_data(self, pending_data: PendingData) -> Self {
        Self {
            pending_data: Some(pending_data),
            ..self
        }
    }

    #[cfg(test)]
    pub async fn for_tests_with_pending() -> Arc<Self> {
        // This is a bit silly with the arc in and out, but since its for tests the ergonomics of
        // having Arc also constructed is nice.
        let context = Self::for_tests();
        let pending_data = super::tests::create_pending_data(context.storage.clone()).await;
        let context = (*context).clone().with_pending_data(pending_data);

        Arc::new(context)
    }
}
