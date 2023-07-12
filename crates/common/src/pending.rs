use std::sync::{Arc, RwLock};

use crate::{BlockHash, BlockWithBody, StateCommitment, StateUpdate};

#[derive(Clone, Default)]
pub struct PendingData(Arc<RwLock<Inner>>);

#[derive(Clone, Default)]
struct Inner {
    block: Arc<BlockWithBody>,
    state_update: Arc<StateUpdate>,
}

impl PendingData {
    /// Returns the inner pending block if is valid for the latest block.
    ///
    /// That is, if the pending block's parent hash matches latest.
    pub fn block(&self, latest: BlockHash) -> Option<Arc<BlockWithBody>> {
        self.0
            .read()
            .ok()
            .map(|inner| (inner.block.header.parent_hash == latest).then_some(inner.block.clone()))
            .flatten()
    }

    /// Returns the inner pending state update if is valid for the latest block.
    ///
    /// That is, if the pending block's state update parent commitment matches latest.
    pub fn state_update(&self, latest: StateCommitment) -> Option<Arc<StateUpdate>> {
        self.0
            .read()
            .ok()
            .map(|inner| {
                (inner.state_update.parent_state_commitment == latest)
                    .then_some(inner.state_update.clone())
            })
            .flatten()
    }

    pub fn block_unchecked(&self) -> Arc<BlockWithBody> {
        self.0
            .read()
            .ok()
            .map(|inner| inner.block.clone())
            .unwrap_or_default()
    }

    pub fn state_update_unchecked(&self) -> Arc<StateUpdate> {
        self.0
            .read()
            .ok()
            .map(|inner| inner.state_update.clone())
            .unwrap_or_default()
    }

    pub fn set_block(&self, block: Arc<BlockWithBody>) {
        match self.0.write() {
            Ok(mut inner) => inner.block = block,
            Err(mut poison) => {
                // Not much we can do here, except reset the data.
                let inner = poison.get_mut();
                inner.block = block;
                inner.state_update = Default::default();
            }
        }
    }

    pub fn set_state_update(&self, state_update: Arc<StateUpdate>) {
        match self.0.write() {
            Ok(mut inner) => inner.state_update = state_update,
            Err(mut poison) => {
                // Not much we can do here, except reset the data.
                let inner = poison.get_mut();
                inner.state_update = state_update;
                inner.block = Default::default();
            }
        }
    }
}
