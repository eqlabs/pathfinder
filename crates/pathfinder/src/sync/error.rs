use p2p::PeerData;
use pathfinder_common::{BlockNumber, SignedBlockHeader};

#[derive(Debug, thiserror::Error)]
pub(super) enum SyncError {
    #[error(transparent)]
    DatabaseError(#[from] anyhow::Error),
    #[error("Header signature verification failed")]
    BadHeaderSignature(PeerData<SignedBlockHeader>),
    #[error("Block hash verification failed")]
    BadBlockHash(PeerData<SignedBlockHeader>),
    #[error("Discontinuity in header chain")]
    Discontinuity(PeerData<SignedBlockHeader>),
    #[error("State diff signature verification failed")]
    BadStateDiffSignature(PeerData<BlockNumber>),
    #[error("State diff commitment mismatch")]
    StateDiffCommitmentMismatch(PeerData<BlockNumber>),
}
