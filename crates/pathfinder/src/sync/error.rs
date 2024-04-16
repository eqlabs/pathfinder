use p2p::{libp2p::PeerId, PeerData};
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
    #[error("State diff signature verification failed")]
    BadStateDiffSignature(PeerId),
    #[error("State diff commitment mismatch")]
    StateDiffCommitmentMismatch(PeerId),
    #[error("Invalid class definition layout")]
    BadClassLayout(PeerId),
    #[error("Unexpected class definition")]
    UnexpectedClass(PeerId),
    #[error("Class hash verification failed")]
    BadClassHash(PeerId),
    #[error("Event commitment mismatch")]
    EventCommitmentMismatch(PeerId),
}
