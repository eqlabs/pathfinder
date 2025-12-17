use std::sync::Arc;

use p2p::libp2p::PeerId;
use p2p::PeerData;
use pathfinder_common::{BlockNumber, ClassHash, SignedBlockHeader};
use pathfinder_storage::StorageError;

#[derive(Debug, thiserror::Error, Clone)]
pub(super) enum SyncError {
    /// This is the only variant that causes any sync process to halt and does
    /// not result in a retry.
    #[error(transparent)]
    Fatal(#[from] Arc<anyhow::Error>),
    #[error("Block hash verification failed")]
    BadBlockHash(PeerId),
    #[error("Class hash verification failed")]
    BadClassHash(PeerId),
    #[error("Invalid class definition layout")]
    BadClassLayout(PeerId),
    #[error("Header signature verification failed")]
    BadHeaderSignature(PeerId),
    #[error("Transaction hash verification failed")]
    BadTransactionHash(PeerId),
    #[error("Incorrect cairo definition")]
    CairoDefinitionError(PeerId),
    #[error("Class definitions and declarations mismatch")]
    ClassDefinitionsDeclarationsMismatch(PeerId),
    #[error("Class hash computation failed")]
    ClassHashComputationError(PeerId),
    #[error("Contract's class is missing")]
    ContractClassMissing(PeerId),
    #[error("Discontinuity in header chain")]
    Discontinuity(PeerId),
    #[error("Event commitment mismatch")]
    EventCommitmentMismatch(PeerId),
    #[error("Mismatch between events and transactions")]
    EventsTransactionsMismatch(PeerId),
    #[error("Fetching casm from feeder gateway failed")]
    FetchingCasmFailed,
    #[error("Incorrect class definition count")]
    IncorrectClassDefinitionCount(PeerId),
    #[error("Incorrect state diff count")]
    IncorrectStateDiffCount(PeerId),
    #[error("Invalid data in DTO")]
    InvalidDto(PeerId),
    #[error("Incorrect sierra definition")]
    SierraDefinitionError(PeerId),
    #[error("State diff commitment mismatch")]
    StateDiffCommitmentMismatch(PeerId),
    #[error("State root mismatch")]
    StateRootMismatch(PeerId),
    #[error("Too few events")]
    TooFewEvents(PeerId),
    #[error("Too few transactions")]
    TooFewTransactions(PeerId),
    #[error("Too many events")]
    TooManyEvents(PeerId),
    #[error("Too many transactions")]
    TooManyTransactions(PeerId),
    #[error("Transaction commitment mismatch")]
    TransactionCommitmentMismatch(PeerId),
    #[error("Unexpected class definition")]
    UnexpectedClass(PeerId),
}

impl PartialEq for SyncError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (SyncError::Fatal(x), SyncError::Fatal(y)) => x.to_string() == y.to_string(),
            (SyncError::BadBlockHash(x), SyncError::BadBlockHash(y)) => x == y,
            (SyncError::BadClassLayout(x), SyncError::BadClassLayout(y)) => x == y,
            (SyncError::BadHeaderSignature(x), SyncError::BadHeaderSignature(y)) => x == y,
            (SyncError::CairoDefinitionError(x), SyncError::CairoDefinitionError(y)) => x == y,
            (
                SyncError::ClassDefinitionsDeclarationsMismatch(x),
                SyncError::ClassDefinitionsDeclarationsMismatch(y),
            ) => x == y,
            (SyncError::ClassHashComputationError(x), SyncError::ClassHashComputationError(y)) => {
                x == y
            }
            (SyncError::Discontinuity(x), SyncError::Discontinuity(y)) => x == y,
            (SyncError::EventCommitmentMismatch(x), SyncError::EventCommitmentMismatch(y)) => {
                x == y
            }
            (
                SyncError::EventsTransactionsMismatch(x),
                SyncError::EventsTransactionsMismatch(y),
            ) => x == y,
            (SyncError::FetchingCasmFailed, SyncError::FetchingCasmFailed) => true,
            (
                SyncError::IncorrectClassDefinitionCount(x),
                SyncError::IncorrectClassDefinitionCount(y),
            ) => x == y,
            (SyncError::IncorrectStateDiffCount(x), SyncError::IncorrectStateDiffCount(y)) => {
                x == y
            }
            (SyncError::InvalidDto(x), SyncError::InvalidDto(y)) => x == y,
            (SyncError::SierraDefinitionError(x), SyncError::SierraDefinitionError(y)) => x == y,
            (
                SyncError::StateDiffCommitmentMismatch(x),
                SyncError::StateDiffCommitmentMismatch(y),
            ) => x == y,
            (SyncError::StateRootMismatch(x), SyncError::StateRootMismatch(y)) => x == y,
            (SyncError::TooFewEvents(x), SyncError::TooFewEvents(y)) => x == y,
            (SyncError::TooFewTransactions(x), SyncError::TooFewTransactions(y)) => x == y,
            (SyncError::TooManyEvents(x), SyncError::TooManyEvents(y)) => x == y,
            (SyncError::TooManyTransactions(x), SyncError::TooManyTransactions(y)) => x == y,
            (
                SyncError::TransactionCommitmentMismatch(x),
                SyncError::TransactionCommitmentMismatch(y),
            ) => x == y,
            (SyncError::UnexpectedClass(x), SyncError::UnexpectedClass(y)) => x == y,
            _ => false,
        }
    }
}

impl From<anyhow::Error> for SyncError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fatal(Arc::new(e))
    }
}

impl From<StorageError> for SyncError {
    fn from(e: StorageError) -> Self {
        // StorageError is always fatal
        Self::Fatal(Arc::new(e.into()))
    }
}
