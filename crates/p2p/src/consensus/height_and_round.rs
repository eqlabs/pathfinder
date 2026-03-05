use libp2p::bytes::{Buf, BufMut};

/// Height of a proposal.
pub type Height = u64;

/// Round (non-nil) of a proposal.
pub type NonNilRound = u32;

/// Height and (non-nil) round of a proposal.
///
/// This serves as the `stream_id` when sending messages via Gossip.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeightAndRound(Height, NonNilRound);

impl HeightAndRound {
    pub fn new(height: Height, round: NonNilRound) -> Self {
        Self(height, round)
    }

    pub fn height(&self) -> Height {
        self.0
    }

    pub fn round(&self) -> NonNilRound {
        self.1
    }
}

impl From<(Height, NonNilRound)> for HeightAndRound {
    fn from(value: (Height, NonNilRound)) -> Self {
        Self(value.0, value.1)
    }
}

impl From<HeightAndRound> for Vec<u8> {
    fn from(value: HeightAndRound) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.put_u64(value.height());
        bytes.put_u32(value.round());
        bytes
    }
}

impl TryFrom<Vec<u8>> for HeightAndRound {
    type Error = std::io::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != 12 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid length",
            ));
        }
        let mut bytes = value.as_slice();
        let height = bytes.get_u64();
        let round = bytes.get_u32();
        Ok(HeightAndRound(height, round))
    }
}

impl std::fmt::Display for HeightAndRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}:{})", self.height(), self.round())
    }
}
