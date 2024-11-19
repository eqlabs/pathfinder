use std::sync::{LazyLock, Mutex, MutexGuard};

use blockifier::execution::contract_class::ContractClass;
use cached::{Cached, SizedCache};
use pathfinder_common::BlockNumber;
use starknet_api::core::ClassHash as StarknetClassHash;

pub static GLOBAL_CACHE: LazyLock<LruContractCache> = LazyLock::new(LruContractCache::new);

#[derive(Clone)]
pub struct Entry {
    pub definition: ContractClass,
    /// The height at which the class was declared
    pub height: BlockNumber,
}

/// An LRU contract class cache
pub struct LruContractCache(Mutex<SizedCache<StarknetClassHash, Entry>>);

impl LruContractCache {
    fn new() -> Self {
        Self(Mutex::new(SizedCache::with_size(128)))
    }

    fn locked_cache(&self) -> MutexGuard<'_, SizedCache<StarknetClassHash, Entry>> {
        self.0.lock().unwrap()
    }

    pub fn get(&self, class_hash: &StarknetClassHash) -> Option<Entry> {
        self.locked_cache().cache_get(class_hash).cloned()
    }

    pub fn set(
        &self,
        class_hash: StarknetClassHash,
        contract_class: ContractClass,
        block_number: BlockNumber,
    ) {
        self.locked_cache().cache_set(
            class_hash,
            Entry {
                definition: contract_class.clone(),
                height: block_number,
            },
        );
    }
}
