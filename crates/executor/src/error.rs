use blockifier::execution::errors::{
    ConstructorEntryPointExecutionError,
    EntryPointExecutionError as BlockifierEntryPointExecutionError,
    PreExecutionError,
};
use blockifier::execution::stack_trace::gen_transaction_execution_error_trace;
use blockifier::state::errors::StateError;
use blockifier::transaction::errors::TransactionExecutionError as BlockifierTransactionExecutionError;

use crate::error_stack::ErrorStack;

#[derive(Debug)]
pub enum CallError {
    ContractNotFound,
    InvalidMessageSelector,
    ContractError(anyhow::Error, ErrorStack),
    Internal(anyhow::Error),
    Custom(anyhow::Error),
}

impl From<BlockifierTransactionExecutionError> for CallError {
    fn from(value: BlockifierTransactionExecutionError) -> Self {
        use BlockifierTransactionExecutionError::*;

        let error_stack = gen_transaction_execution_error_trace(&value);

        match value {
            ContractConstructorExecutionFailed(
                ConstructorEntryPointExecutionError::ExecutionError { error, .. },
            ) => match error {
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::EntryPointNotFound(_),
                ) => Self::InvalidMessageSelector,
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::UninitializedStorageAddress(_),
                ) => Self::ContractNotFound,
                _ => Self::ContractError(error.into(), error_stack.into()),
            },
            ExecutionError { error, .. } => match error {
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::EntryPointNotFound(_),
                ) => Self::InvalidMessageSelector,
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::UninitializedStorageAddress(_),
                ) => Self::ContractNotFound,
                _ => Self::ContractError(error.into(), error_stack.into()),
            },
            ValidateTransactionError { error, .. } => match error {
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::EntryPointNotFound(_),
                ) => Self::InvalidMessageSelector,
                BlockifierEntryPointExecutionError::PreExecutionError(
                    PreExecutionError::UninitializedStorageAddress(_),
                ) => Self::ContractNotFound,
                _ => Self::ContractError(error.into(), error_stack.into()),
            },
            e => Self::ContractError(e.into(), error_stack.into()),
        }
    }
}

impl CallError {
    pub fn from_entry_point_execution_error(
        error: BlockifierEntryPointExecutionError,
        contract_address: &starknet_api::core::ContractAddress,
        class_hash: &starknet_api::core::ClassHash,
        entry_point: &starknet_api::core::EntryPointSelector,
    ) -> Self {
        let error = BlockifierTransactionExecutionError::ExecutionError {
            error,
            class_hash: *class_hash,
            storage_address: *contract_address,
            selector: *entry_point,
        };
        error.into()
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
        error_stack: ErrorStack,
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
        let error_stack = gen_transaction_execution_error_trace(&error);

        Self::ExecutionError {
            transaction_index,
            error: error.to_string(),
            error_stack: error_stack.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod transaction_errors_are_mapped_correctly {
        //! Some variants in the blockifier are opaque and omit the inner
        //! error's data. We've patched this manually and this tests
        //! ensures we don't accidentally stutter once the blockifier fixes
        //! this.
        use blockifier::execution::errors::EntryPointExecutionError;

        use super::*;

        #[test]
        fn contract_constructor_execution_failed() {
            let child = EntryPointExecutionError::RecursionDepthExceeded;
            let expected = format!(
                "Contract constructor execution has failed:\n0: Error in the contract class \
                 constructor (contract address: \
                 0x0000000000000000000000000000000000000000000000000000000000000000, class hash: \
                 0x0000000000000000000000000000000000000000000000000000000000000000, selector: \
                 UNKNOWN):\n{child}\n"
            );

            let err = BlockifierTransactionExecutionError::ContractConstructorExecutionFailed(
                ConstructorEntryPointExecutionError::ExecutionError {
                    error: child,
                    class_hash: Default::default(),
                    contract_address: Default::default(),
                    constructor_selector: Default::default(),
                },
            );
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
            let expected = format!(
                "Contract constructor execution has failed:\n0: Error in the contract class \
                 constructor (contract address: \
                 0x0000000000000000000000000000000000000000000000000000000000000000, class hash: \
                 0x0000000000000000000000000000000000000000000000000000000000000000, selector: \
                 UNKNOWN):\n{child}\n"
            );

            let err = BlockifierTransactionExecutionError::ContractConstructorExecutionFailed(
                ConstructorEntryPointExecutionError::ExecutionError {
                    error: child,
                    class_hash: Default::default(),
                    contract_address: Default::default(),
                    constructor_selector: Default::default(),
                },
            );
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
            let expected = format!(
                r"Transaction validation has failed:
0: Error in the called contract (contract address: 0x0000000000000000000000000000000000000000000000000000000000000000, class hash: 0x0000000000000000000000000000000000000000000000000000000000000000, selector: 0x0000000000000000000000000000000000000000000000000000000000000000):
{child}
"
            );

            let err = BlockifierTransactionExecutionError::ValidateTransactionError {
                error: child,
                class_hash: Default::default(),
                storage_address: Default::default(),
                selector: Default::default(),
            };
            let err = TransactionExecutionError::new(0, err);
            let err = match err {
                TransactionExecutionError::ExecutionError { error, .. } => error,
                _ => unreachable!("unexpected variant"),
            };

            assert_eq!(err, expected);
        }
    }
}
