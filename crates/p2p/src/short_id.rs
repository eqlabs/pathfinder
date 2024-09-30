use std::fmt::{Debug, Display};
use std::str;

use libp2p::PeerId;

#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShortId([u8; 2]);

impl Debug for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(str::from_utf8(&self.0).expect("PeerId is ASCII"))
    }
}

impl Display for ShortId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(self, f)
    }
}

impl From<&PeerId> for ShortId {
    fn from(peer_id: &PeerId) -> Self {
        let s = peer_id.to_string();
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

#[allow(dead_code)]
pub trait PeerIdExt {
    fn short(&self) -> ShortId;
}

impl PeerIdExt for PeerId {
    fn short(&self) -> ShortId {
        ShortId::from(self)
    }
}
