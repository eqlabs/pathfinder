use crate::{state::PendingData, storage::Storage};

pub mod method;
pub mod types;

pub struct RpcContext {
    pub storage: Storage,
    pub pending_data: Option<PendingData>,
}

impl RpcContext {
    pub fn new(storage: Storage) -> Self {
        Self {
            storage,
            pending_data: None,
        }
    }

    #[cfg(test)]
    pub fn for_tests() -> std::sync::Arc<Self> {
        let storage = super::tests::setup_storage();
        std::sync::Arc::new(Self::new(storage))
    }

    pub fn with_pending_data(self, pending_data: PendingData) -> Self {
        Self {
            pending_data: Some(pending_data),
            ..self
        }
    }

    #[cfg(test)]
    pub async fn for_tests_with_pending() -> std::sync::Arc<Self> {
        let storage = super::tests::setup_storage();
        let pending_data = super::tests::create_pending_data(storage.clone()).await;
        std::sync::Arc::new(Self::new(storage).with_pending_data(pending_data))
    }
}
