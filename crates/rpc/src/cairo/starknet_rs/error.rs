use starknet_in_rust::core::errors::state_errors::StateError;
use starknet_in_rust::transaction::error::TransactionError;

#[derive(Debug)]
pub enum CallError {
    ContractNotFound,
    InvalidMessageSelector,
    Reverted(String),
    Internal(anyhow::Error),
}

impl From<TransactionError> for CallError {
    fn from(value: starknet_in_rust::transaction::error::TransactionError) -> Self {
        match value {
            TransactionError::EntryPointNotFound => Self::InvalidMessageSelector,
            TransactionError::FailToReadClassHash => Self::ContractNotFound,
            TransactionError::State(StateError::NoneClassHash(_)) => Self::ContractNotFound,
            e => Self::Internal(anyhow::anyhow!("Internal error: {}", e)),
        }
    }
}

impl From<anyhow::Error> for CallError {
    fn from(value: anyhow::Error) -> Self {
        Self::Internal(value)
    }
}
