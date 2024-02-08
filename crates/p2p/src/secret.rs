use libp2p::identity::Keypair;
use sha3::Digest;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secret value used to make certain decisions unpredictable.
///
/// This value is used to pick the peer to be evicted during the peer eviction process.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; 32]);

impl Secret {
    pub fn new(identity: &Keypair) -> Self {
        Self(identity.derive_secret(b"pathfinder").unwrap())
    }

    /// Updates the given hasher with the secret.
    pub fn hash_into(&self, hasher: &mut impl Digest) {
        // Intentionally takes a reference to avoid copying the secret.
        #[allow(clippy::needless_borrows_for_generic_args)]
        hasher.update(&self.0);
    }
}
