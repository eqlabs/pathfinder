use std::sync::{LazyLock, Mutex, MutexGuard};

use blockifier::execution::contract_class::RunnableContractClass;
use blockifier::state::errors::StateError;
use blockifier::state::state_api::StateResult;
use cached::{Cached, SizedCache};
use pathfinder_common::BlockNumber;
use starknet_api::core::ClassHash as StarknetClassHash;
use tracing::warn;

pub static GLOBAL_CACHE: LazyLock<LruContractCache> = LazyLock::new(LruContractCache::new);

#[derive(Clone)]
pub struct Entry {
    pub definition: RunnableContractClass,
    /// The height at which the class was declared
    pub height: BlockNumber,
}

/// An LRU contract class cache
pub struct LruContractCache(Mutex<SizedCache<StarknetClassHash, Entry>>);

impl LruContractCache {
    fn new() -> Self {
        Self(Mutex::new(SizedCache::with_size(128)))
    }

    fn locked_cache(&self) -> StateResult<MutexGuard<'_, SizedCache<StarknetClassHash, Entry>>> {
        self.0.lock().map_err(|err| {
            warn!("Contract class cache lock is poisoned. Cause: {}.", err);
            StateError::StateReadError("Poisoned lock".to_string())
        })
    }

    pub fn get(&self, class_hash: &StarknetClassHash) -> StateResult<Option<Entry>> {
        Ok(self.locked_cache()?.cache_get(class_hash).cloned())
    }

    pub fn set(
        &self,
        class_hash: StarknetClassHash,
        contract_class: RunnableContractClass,
        block_number: BlockNumber,
    ) -> StateResult<()> {
        self.locked_cache()?.cache_set(
            class_hash,
            Entry {
                definition: contract_class.clone(),
                height: block_number,
            },
        );

        Ok(())
    }
}
