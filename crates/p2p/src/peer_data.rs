use fake::Dummy;
use libp2p::PeerId;

/// Data received from a specific peer.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerData<T> {
    pub peer: PeerId,
    pub data: T,
}

impl<T> PeerData<T> {
    pub fn new(peer: PeerId, data: T) -> Self {
        Self { peer, data }
    }

    pub fn for_tests(data: T) -> Self {
        Self {
            peer: PeerId::random(),
            data,
        }
    }

    pub fn map<U, F>(self, f: F) -> PeerData<U>
    where
        F: FnOnce(T) -> U,
    {
        PeerData {
            peer: self.peer,
            data: f(self.data),
        }
    }
}

impl<T, U: Dummy<T>> Dummy<T> for PeerData<U> {
    fn dummy_with_rng<R: rand::prelude::Rng + ?Sized>(config: &T, rng: &mut R) -> Self {
        let digest = rng.gen::<[u8; 32]>();
        let multihash = libp2p::multihash::Multihash::wrap(0x0, &digest)
            .expect("The digest size is never too large");

        PeerData {
            peer: PeerId::from_multihash(multihash).expect("Valid multihash"),
            data: U::dummy_with_rng(config, rng),
        }
    }
}
