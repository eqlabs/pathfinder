pub(crate) mod block;
pub(crate) mod call;
pub(crate) mod class;
pub(crate) mod concurrent_block;
pub(crate) mod error;
pub(crate) mod error_stack;
pub(crate) mod estimate;
pub(crate) mod execution_state;
pub(crate) mod felt;
pub(crate) mod lru_cache;
pub(crate) mod pending;
pub(crate) mod simulate;
pub(crate) mod state_reader;
pub(crate) mod transaction;
pub mod types;
pub mod worker_pool;

pub use block::{BlockExecutor, BlockExecutorExt};
// re-export blockifier transaction type since it's exposed on our API
pub use blockifier::blockifier_versioned_constants::{VersionedConstants, VersionedConstantsError};
pub use blockifier::transaction::account_transaction::{
    AccountTransaction,
    ExecutionFlags as AccountTransactionExecutionFlags,
};
pub use blockifier::transaction::transaction_execution::Transaction;
pub use call::call;
pub use class::{parse_casm_definition, parse_deprecated_class_definition};
pub use concurrent_block::{ConcurrentBlockExecutor, ConcurrentStateReader};
pub use error::{CallError, TransactionExecutionError};
pub use error_stack::{CallFrame, ErrorStack, Frame};
pub use estimate::estimate;
pub use execution_state::{
    ExecutionState,
    L1BlobDataAvailability,
    PathfinderExecutionState,
    VersionedConstantsMap,
};
pub use felt::{IntoFelt, IntoStarkFelt};
pub use simulate::{simulate, trace, BlockTraces, TraceCache, TransactionTraces};
pub use starknet_api::contract_class::ClassInfo;
pub use state_reader::{ConcurrentStorageAdapter, NativeClassCache};
pub use worker_pool::{ExecutorWorkerPool, DEFAULT_STACK_SIZE};

// Re-export blockifier types needed for the concurrent executor
pub mod blockifier_reexports {
    pub use blockifier::concurrency::worker_pool::WorkerPool;
    pub use blockifier::state::cached_state::CachedState;
}
