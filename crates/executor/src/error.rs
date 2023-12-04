use blockifier::{
    execution::errors::{
        EntryPointExecutionError as BlockifierEntryPointExecutionError, PreExecutionError,
    },
    state::errors::StateError,
    transaction::errors::TransactionExecutionError as BlockifierTransactionExecutionError,
};

#[derive(Debug)]
pub enum CallError {
    ContractNotFound,
    InvalidMessageSelector,
    ContractError(anyhow::Error),
    Internal(anyhow::Error),
    Custom(anyhow::Error),
}

impl From<BlockifierTransactionExecutionError> for CallError {
    fn from(value: BlockifierTransactionExecutionError) -> Self {
        use BlockifierTransactionExecutionError::*;
        match value {
            ContractConstructorExecutionFailed(e)
            | EntryPointExecutionError(e)
            | ExecutionError(e)
            | ValidateTransactionError(e) => match e {
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::EntryPointNotFound(_),
                ) => Self::InvalidMessageSelector,
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::UninitializedStorageAddress(_),
                ) => Self::ContractNotFound,
                _ => Self::Custom(e.into()),
            },
            e => Self::Custom(e.into()),
        }
    }
}

impl From<BlockifierEntryPointExecutionError> for CallError {
    fn from(e: BlockifierEntryPointExecutionError) -> Self {
        match e {
            BlockifierEntryPointExecutionError::PreExecutionError(
                PreExecutionError::EntryPointNotFound(_),
            ) => Self::InvalidMessageSelector,
            BlockifierEntryPointExecutionError::PreExecutionError(
                PreExecutionError::UninitializedStorageAddress(_),
            ) => Self::ContractNotFound,
            _ => Self::ContractError(e.into()),
        }
    }
}

impl From<StateError> for CallError {
    fn from(e: StateError) -> Self {
        match e {
            StateError::StateReadError(_) => Self::Internal(e.into()),
            _ => Self::Custom(anyhow::anyhow!("State error: {}", e)),
        }
    }
}

impl From<starknet_api::StarknetApiError> for CallError {
    fn from(value: starknet_api::StarknetApiError) -> Self {
        Self::Custom(value.into())
    }
}

impl From<anyhow::Error> for CallError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}

#[derive(Debug)]
pub enum TransactionExecutionError {
    ExecutionError {
        transaction_index: usize,
        error: String,
    },
    Internal(anyhow::Error),
    Custom(anyhow::Error),
}

impl From<StateError> for TransactionExecutionError {
    fn from(e: StateError) -> Self {
        match e {
            StateError::StateReadError(_) => Self::Internal(e.into()),
            _ => Self::Custom(anyhow::anyhow!("State error: {}", e)),
        }
    }
}

impl From<starknet_api::StarknetApiError> for TransactionExecutionError {
    fn from(value: starknet_api::StarknetApiError) -> Self {
        Self::Custom(value.into())
    }
}

impl From<anyhow::Error> for TransactionExecutionError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}
