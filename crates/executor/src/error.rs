use blockifier::{
    execution::errors::{EntryPointExecutionError, PreExecutionError},
    transaction::errors::TransactionExecutionError,
};

#[derive(Debug)]
pub enum CallError {
    ContractNotFound,
    InvalidMessageSelector,
    Reverted(String),
    Internal(anyhow::Error),
}

impl From<TransactionExecutionError> for CallError {
    fn from(value: TransactionExecutionError) -> Self {
        match value {
            TransactionExecutionError::ContractConstructorExecutionFailed(e)
            | TransactionExecutionError::EntryPointExecutionError(e)
            | TransactionExecutionError::ExecutionError(e)
            | TransactionExecutionError::ValidateTransactionError(e) => match e {
                EntryPointExecutionError::PreExecutionError(
                    PreExecutionError::EntryPointNotFound(_),
                ) => Self::InvalidMessageSelector,
                EntryPointExecutionError::PreExecutionError(
                    PreExecutionError::UninitializedStorageAddress(_),
                ) => Self::ContractNotFound,
                _ => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
            },
            e => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
        }
    }
}

impl From<EntryPointExecutionError> for CallError {
    fn from(e: EntryPointExecutionError) -> Self {
        match e {
            EntryPointExecutionError::PreExecutionError(PreExecutionError::EntryPointNotFound(
                _,
            )) => Self::InvalidMessageSelector,
            EntryPointExecutionError::PreExecutionError(
                PreExecutionError::UninitializedStorageAddress(_),
            ) => Self::ContractNotFound,
            _ => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
        }
    }
}

impl From<starknet_api::StarknetApiError> for CallError {
    fn from(value: starknet_api::StarknetApiError) -> Self {
        Self::Internal(value.into())
    }
}

impl From<anyhow::Error> for CallError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}
