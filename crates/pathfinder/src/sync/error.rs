use std::sync::Arc;

use p2p::libp2p::PeerId;
use p2p::PeerData;
use pathfinder_common::{BlockNumber, ClassHash, SignedBlockHeader};

#[derive(Debug, thiserror::Error)]
pub(super) enum SyncError {
    /// This is the only variant that causes any sync process to halt and does
    /// not result in a retry.
    #[error(transparent)]
    Fatal(#[from] anyhow::Error),
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
    #[error("Discontinuity in header chain")]
    Discontinuity(PeerId),
    #[error("Event commitment mismatch")]
    EventCommitmentMismatch(PeerId),
    #[error("Mismatch between events and transactions")]
    EventsTransactionsMismatch(PeerId),
    #[error("Fetching casm from feeder gateway failed")]
    FetchingCasmFailed,
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
    TooFewTransactions,
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
            (SyncError::TooFewTransactions, SyncError::TooFewTransactions) => true,
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

impl SyncError {
    /// Temporary cast to allow refactoring towards SyncError2.
    pub fn into_v2(self) -> PeerData<SyncError2> {
        match self {
            SyncError::Fatal(e) => PeerData::new(PeerId::random(), SyncError2::Other(Arc::new(e))),
            SyncError::BadHeaderSignature(x) => PeerData::new(x, SyncError2::BadHeaderSignature),
            SyncError::BadBlockHash(x) => PeerData::new(x, SyncError2::BadBlockHash),
            SyncError::Discontinuity(x) => PeerData::new(x, SyncError2::Discontinuity),
            SyncError::StateDiffCommitmentMismatch(x) => {
                PeerData::new(x, SyncError2::StateDiffCommitmentMismatch)
            }
            SyncError::BadClassLayout(x) => PeerData::new(x, SyncError2::BadClassLayout),
            SyncError::ClassHashComputationError(x) => {
                PeerData::new(x, SyncError2::ClassHashComputationError)
            }
            SyncError::UnexpectedClass(x) => PeerData::new(x, SyncError2::UnexpectedClass),
            SyncError::EventCommitmentMismatch(x) => {
                PeerData::new(x, SyncError2::EventCommitmentMismatch)
            }
            SyncError::TransactionCommitmentMismatch(x) => {
                PeerData::new(x, SyncError2::TransactionCommitmentMismatch)
            }
            SyncError::StateRootMismatch(x) => PeerData::new(x, SyncError2::StateRootMismatch),
            SyncError::BadTransactionHash(x) => PeerData::new(x, SyncError2::BadTransactionHash),
            SyncError::BadClassHash(x) => PeerData::new(x, SyncError2::BadClassHash),
            SyncError::FetchingCasmFailed => {
                PeerData::new(PeerId::random(), SyncError2::FetchingCasmFailed)
            }
            _ => todo!(),
        }
    }

    /// Temporary cast to allow refactoring towards SyncError2.
    pub fn from_v2(v2: PeerData<SyncError2>) -> Self {
        let PeerData { peer, data } = v2;

        match data {
            SyncError2::BadHeaderSignature => SyncError::BadHeaderSignature(peer),
            SyncError2::BadBlockHash => SyncError::BadBlockHash(peer),
            SyncError2::Discontinuity => SyncError::Discontinuity(peer),
            SyncError2::StateDiffCommitmentMismatch => SyncError::StateDiffCommitmentMismatch(peer),
            SyncError2::BadClassLayout => SyncError::BadClassLayout(peer),
            SyncError2::ClassHashComputationError => SyncError::ClassHashComputationError(peer),
            SyncError2::UnexpectedClass => SyncError::UnexpectedClass(peer),
            SyncError2::EventCommitmentMismatch => SyncError::EventCommitmentMismatch(peer),
            SyncError2::TransactionCommitmentMismatch => {
                SyncError::TransactionCommitmentMismatch(peer)
            }
            SyncError2::StateRootMismatch => SyncError::StateRootMismatch(peer),
            SyncError2::BadTransactionHash => SyncError::BadTransactionHash(peer),
            SyncError2::BadClassHash => SyncError::BadClassHash(peer),
            SyncError2::FetchingCasmFailed => SyncError::FetchingCasmFailed,
            other => SyncError::Fatal(other.into()),
        }
    }
}

#[derive(Debug, thiserror::Error, Clone)]
pub(super) enum SyncError2 {
    #[error(transparent)]
    Other(#[from] Arc<anyhow::Error>),
    #[error("Header signature verification failed")]
    BadHeaderSignature,
    #[error("Block hash verification failed")]
    BadBlockHash,
    #[error("Discontinuity in header chain")]
    Discontinuity,
    #[error("State diff commitment mismatch")]
    StateDiffCommitmentMismatch,
    #[error("Invalid class definition layout")]
    BadClassLayout,
    #[error("Class hash computation failed")]
    ClassHashComputationError,
    #[error("Unexpected class definition")]
    UnexpectedClass,
    #[error("Event commitment mismatch")]
    EventCommitmentMismatch,
    #[error("Too many events")]
    TooManyEvents,
    #[error("Too few events")]
    TooFewEvents,
    #[error("Transaction commitment mismatch")]
    TransactionCommitmentMismatch,
    #[error("Too many transactions")]
    TooManyTransactions,
    #[error("Too few transactions")]
    TooFewTransactions,
    #[error("Invalid data in DTO")]
    InvalidDto,
    #[error("Mismatch between events and transactions")]
    EventsTransactionsMismatch,
    #[error("Incorrect state diff count")]
    IncorrectStateDiffCount,
    #[error("Incorrect class definition count")]
    IncorrectClassDefinitionCount,
    #[error("Incorrect cairo definition")]
    CairoDefinitionError,
    #[error("Incorrect sierra definition")]
    SierraDefinitionError,
    #[error("Class definitions and declarations mismatch")]
    ClassDefinitionsDeclarationsMismatch,
    #[error("State root mismatch")]
    StateRootMismatch,
    #[error("Transaction hash verification failed")]
    BadTransactionHash,
    #[error("Class hash verification failed")]
    BadClassHash,
    #[error("Fetching casm from feeder gateway failed")]
    FetchingCasmFailed,
}

impl PartialEq for SyncError2 {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Other(x), Self::Other(y)) => x.to_string() == y.to_string(),
            (SyncError2::BadHeaderSignature, SyncError2::BadHeaderSignature) => true,
            (SyncError2::BadBlockHash, SyncError2::BadBlockHash) => true,
            (SyncError2::Discontinuity, SyncError2::Discontinuity) => true,
            (SyncError2::StateDiffCommitmentMismatch, SyncError2::StateDiffCommitmentMismatch) => {
                true
            }
            (SyncError2::BadClassLayout, SyncError2::BadClassLayout) => true,
            (SyncError2::ClassHashComputationError, SyncError2::ClassHashComputationError) => true,
            (SyncError2::UnexpectedClass, SyncError2::UnexpectedClass) => true,
            (SyncError2::EventCommitmentMismatch, SyncError2::EventCommitmentMismatch) => true,
            _ => false,
        }
    }
}

impl From<anyhow::Error> for SyncError2 {
    fn from(value: anyhow::Error) -> Self {
        Self::Other(Arc::new(value))
    }
}
