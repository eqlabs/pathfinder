use std::sync::Arc;

use p2p::libp2p::PeerId;
use p2p::PeerData;
use pathfinder_common::{BlockNumber, ClassHash, SignedBlockHeader};

#[derive(Debug, thiserror::Error)]
pub(super) enum SyncError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("Header signature verification failed")]
    BadHeaderSignature(PeerId),
    #[error("Block hash verification failed")]
    BadBlockHash(PeerId),
    #[error("Discontinuity in header chain")]
    Discontinuity(PeerId),
    #[error("State diff commitment mismatch")]
    StateDiffCommitmentMismatch(PeerId),
    #[error("Invalid class definition layout")]
    BadClassLayout(PeerId),
    #[error("Unexpected class definition")]
    UnexpectedClass(PeerId),
    #[error("Event commitment mismatch")]
    EventCommitmentMismatch(PeerId),
    #[error("Transaction commitment mismatch")]
    TransactionCommitmentMismatch(PeerId),
}

impl PartialEq for SyncError {
    fn eq(&self, other: &Self) -> bool {
        todo!();
    }
}

impl SyncError {
    /// Temporary cast to allow refactoring towards SyncError2.
    pub fn into_v2(self) -> PeerData<SyncError2> {
        match self {
            SyncError::Other(e) => PeerData::new(PeerId::random(), SyncError2::Other(Arc::new(e))),
            SyncError::BadHeaderSignature(x) => PeerData::new(x, SyncError2::BadHeaderSignature),
            SyncError::BadBlockHash(x) => PeerData::new(x, SyncError2::BadBlockHash),
            SyncError::Discontinuity(x) => PeerData::new(x, SyncError2::Discontinuity),
            SyncError::StateDiffCommitmentMismatch(x) => {
                PeerData::new(x, SyncError2::StateDiffCommitmentMismatch)
            }
            SyncError::BadClassLayout(x) => PeerData::new(x, SyncError2::BadClassLayout),
            SyncError::UnexpectedClass(x) => PeerData::new(x, SyncError2::UnexpectedClass),
            SyncError::EventCommitmentMismatch(x) => {
                PeerData::new(x, SyncError2::EventCommitmentMismatch)
            }
            SyncError::TransactionCommitmentMismatch(x) => {
                PeerData::new(x, SyncError2::TransactionCommitmentMismatch)
            }
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
            SyncError2::UnexpectedClass => SyncError::UnexpectedClass(peer),
            SyncError2::EventCommitmentMismatch => SyncError::EventCommitmentMismatch(peer),
            SyncError2::TransactionCommitmentMismatch => {
                SyncError::TransactionCommitmentMismatch(peer)
            }
            other => SyncError::Other(other.into()),
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
    #[error("Starknet version not found in db")]
    StarknetVersionNotFound,
    #[error("State diff commitment not found in db")]
    StateDiffCommitmentNotFound,
    #[error("Transaction commitment not found in db")]
    TransactionCommitmentNotFound,
    #[error("State root mismatch")]
    StateRootMismatch,
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
