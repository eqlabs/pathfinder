use p2p::PeerData;
use pathfinder_common::SignedBlockHeader;

#[derive(Debug, thiserror::Error)]
pub(super) enum SyncError {
    #[error(transparent)]
    DatabaseError(#[from] anyhow::Error),
    #[error("Signature verification failed")]
    BadSignature(PeerData<SignedBlockHeader>),
    #[error("Block hash verification failed")]
    BadBlockHash(PeerData<SignedBlockHeader>),
    #[error("Discontinuity in header chain")]
    Discontinuity(PeerData<SignedBlockHeader>),
}

impl SyncError {
    pub fn peer_id_and_data(&self) -> Option<&PeerData<SignedBlockHeader>> {
        match self {
            SyncError::DatabaseError(_) => None,
            SyncError::BadSignature(x) => Some(x),
            SyncError::BadBlockHash(x) => Some(x),
            SyncError::Discontinuity(x) => Some(x),
        }
    }
}
