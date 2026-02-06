use std::sync::Arc;

use blockifier::blockifier::config::WorkerPoolConfig;
use blockifier::concurrency::worker_pool::WorkerPool;
use blockifier::state::cached_state::CachedState;
use blockifier::state::state_api::StateReader;

/// Default stack size for worker threads (62 MiB).
/// This matches blockifier's default for handling deep recursion in Cairo
/// native execution.
pub const DEFAULT_STACK_SIZE: usize = 62 * 1024 * 1024;

/// Wrapper around blockifier's WorkerPool that provides convenient construction
/// and sharing across multiple concurrent executors.
pub struct ExecutorWorkerPool<S: StateReader> {
    pool: Arc<WorkerPool<CachedState<S>>>,
    config: WorkerPoolConfig,
}

impl<S: StateReader + Send + 'static> ExecutorWorkerPool<S> {
    /// Creates a new worker pool with the specified number of workers.
    ///
    /// Uses the default stack size of 62 MiB per worker thread.
    pub fn new(n_workers: usize) -> Self {
        Self::with_config(WorkerPoolConfig {
            n_workers,
            stack_size: DEFAULT_STACK_SIZE,
        })
    }

    /// Creates a new worker pool with the given configuration.
    pub fn with_config(config: WorkerPoolConfig) -> Self {
        let pool = Arc::new(WorkerPool::start(&config));
        Self { pool, config }
    }

    /// Creates a new worker pool using the number of available CPU cores.
    pub fn auto() -> Self {
        let n_workers = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1);
        Self::new(n_workers)
    }

    /// Returns an Arc reference to the underlying worker pool.
    ///
    /// This is used by ConcurrentTransactionExecutor::start_block().
    pub fn get(&self) -> Arc<WorkerPool<CachedState<S>>> {
        self.pool.clone()
    }

    /// Returns the configuration used to create this worker pool.
    pub fn config(&self) -> &WorkerPoolConfig {
        &self.config
    }

    /// Returns the number of workers in this pool.
    pub fn n_workers(&self) -> usize {
        self.config.n_workers
    }
}
