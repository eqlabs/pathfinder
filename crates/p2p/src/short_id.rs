#![allow(dead_code)]

use std::fmt::{Debug, Display};
use std::str;

use libp2p::PeerId;

/// A debug-friendly representation of a `PeerId` that only keeps the last two
/// characters of the base58 representation.
///
/// ### Important
///
/// Do not use it in production, given a large number of peers collisions
/// __will__ occur.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShortId([u8; 2]);

impl Debug for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(str::from_utf8(&self.0).expect("Base58 characters are ASCII"))
    }
}

impl Display for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl From<&PeerId> for ShortId {
    fn from(peer_id: &PeerId) -> Self {
        let s = peer_id.to_base58();
        let s = s.as_bytes();
        let mut short = [0; 2];
        short.copy_from_slice(&s[s.len() - 2..]);
        ShortId(short)
    }
}

impl From<PeerId> for ShortId {
    fn from(peer_id: PeerId) -> Self {
        ShortId::from(&peer_id)
    }
}

pub mod prelude {
    use std::collections::{BTreeSet, HashMap, HashSet};

    use libp2p::PeerId;

    use super::ShortId;

    pub trait Short {
        fn short(&self) -> ShortId;
    }

    impl Short for PeerId {
        fn short(&self) -> ShortId {
            ShortId::from(self)
        }
    }

    pub trait IntoKeysShort {
        fn into_keys_short(self) -> BTreeSet<ShortId>;
    }

    impl<T, U, V> IntoKeysShort for T
    where
        T: IntoIterator<Item = V, IntoIter = U>,
        U: Iterator<Item = V>,
        V: PeerIdField,
    {
        fn into_keys_short(self) -> BTreeSet<ShortId> {
            self.into_iter().map(|x| x.peer_id().short()).collect()
        }
    }

    pub trait KeysShort {
        fn keys_short(&self) -> BTreeSet<ShortId>;
    }

    impl KeysShort for Vec<PeerId> {
        fn keys_short(&self) -> BTreeSet<ShortId> {
            self.iter().map(Short::short).collect()
        }
    }

    impl KeysShort for HashSet<PeerId> {
        fn keys_short(&self) -> BTreeSet<ShortId> {
            self.iter().map(Short::short).collect()
        }
    }

    impl<T> KeysShort for HashMap<PeerId, T> {
        fn keys_short(&self) -> BTreeSet<ShortId> {
            self.keys().map(Short::short).collect()
        }
    }

    pub trait PeerIdField {
        fn peer_id(&self) -> PeerId;
    }

    impl<T> PeerIdField for (PeerId, T) {
        fn peer_id(&self) -> PeerId {
            self.0
        }
    }

    impl PeerIdField for PeerId {
        fn peer_id(&self) -> PeerId {
            *self
        }
    }
}
