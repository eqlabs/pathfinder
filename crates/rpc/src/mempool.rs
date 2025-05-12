use std::sync::{Arc, Mutex};

use cached::{Cached, TimedCache};
use pathfinder_common::TransactionHash;

#[derive(Clone, Debug)]
pub struct MinimalMempool(Arc<Mutex<TimedCache<TransactionHash, ()>>>);

impl MinimalMempool {
    pub fn new(limit_sec: u64) -> Self {
        Self(Arc::new(Mutex::new(TimedCache::with_lifespan(limit_sec))))
    }

    pub fn contains_key(&self, hash: &TransactionHash) -> bool {
        let mut cache = self.0.lock().unwrap();
        let res = cache.cache_get(hash);
        res.is_some()
    }

    pub fn insert_key(&self, hash: TransactionHash) {
        let mut cache = self.0.lock().unwrap();
        let res = cache.cache_set(hash, ());
        if res.is_some() {
            tracing::warn!("repeated tx hash in mempool: {}", hash);
        }
    }

    pub fn flush(&self) {
        let mut cache = self.0.lock().unwrap();
        cache.flush();
    }
}
