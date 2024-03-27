use p2p::PeerData;
use pathfinder_common::SignedBlockHeader;

#[derive(Debug, thiserror::Error)]
pub(super) enum HeaderSyncError {
    #[error(transparent)]
    DatabaseError(#[from] anyhow::Error),
    #[error("Signature verification failed")]
    BadSignature(PeerData<SignedBlockHeader>),
    #[error("Block hash verification failed")]
    BadBlockHash(PeerData<SignedBlockHeader>),
    #[error("Discontinuity in header chain")]
    Discontinuity(PeerData<SignedBlockHeader>),
}

impl HeaderSyncError {
    pub fn peer_id_and_data(&self) -> Option<&PeerData<SignedBlockHeader>> {
        match self {
            HeaderSyncError::DatabaseError(_) => None,
            HeaderSyncError::BadSignature(x) => Some(x),
            HeaderSyncError::BadBlockHash(x) => Some(x),
            HeaderSyncError::Discontinuity(x) => Some(x),
        }
    }
}
