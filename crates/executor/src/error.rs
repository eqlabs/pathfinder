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

impl TransactionExecutionError {
    pub fn new(transaction_index: usize, error: BlockifierTransactionExecutionError) -> Self {
        Self::ExecutionError {
            transaction_index,
            error: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod transaction_errors_are_mapped_correctly {
        //! Some variants in the blockifier are opaque and omit the inner error's data. We've patched this manually
        //! and this tests ensures we don't accidentally stutter once the blockifier fixes this.
        use super::*;
        use blockifier::execution::errors::EntryPointExecutionError;

        #[test]
        fn contract_constructor_execution_failed() {
            let child = EntryPointExecutionError::RecursionDepthExceeded;
            let expected = format!("Contract constructor execution has failed: {child}");

            let err =
                BlockifierTransactionExecutionError::ContractConstructorExecutionFailed(child);
            let err = TransactionExecutionError::new(0, err);
            let err = match err {
                TransactionExecutionError::ExecutionError { error, .. } => error,
                _ => unreachable!("unexpected variant"),
            };

            assert_eq!(err, expected);
        }

        #[test]
        fn execution_error() {
            let child = EntryPointExecutionError::RecursionDepthExceeded;
            let expected = format!("Transaction execution has failed: {child}");

            let err = BlockifierTransactionExecutionError::ExecutionError(child);
            let err = TransactionExecutionError::new(0, err);
            let err = match err {
                TransactionExecutionError::ExecutionError { error, .. } => error,
                _ => unreachable!("unexpected variant"),
            };

            assert_eq!(err, expected);
        }

        #[test]
        fn validate_transaction_error() {
            let child = EntryPointExecutionError::RecursionDepthExceeded;
            let expected = format!("Transaction validation has failed: {child}");

            let err = BlockifierTransactionExecutionError::ValidateTransactionError(child);
            let err = TransactionExecutionError::new(0, err);
            let err = match err {
                TransactionExecutionError::ExecutionError { error, .. } => error,
                _ => unreachable!("unexpected variant"),
            };

            assert_eq!(err, expected);
        }
    }
}
