use libp2p::bytes::{Buf, BufMut};

/// Height and round of the proposal.
///
/// This serves as the `stream_id` when sending messages via Gossip.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HeightAndRound {
    height: u64,
    round: u32,
}

impl HeightAndRound {
    pub fn new(height: u64, round: u32) -> Self {
        Self { height, round }
    }

    pub fn height(&self) -> u64 {
        self.height
    }

    pub fn round(&self) -> u32 {
        self.round
    }
}

impl From<(u64, u32)> for HeightAndRound {
    fn from(value: (u64, u32)) -> Self {
        Self {
            height: value.0,
            round: value.1,
        }
    }
}

impl From<HeightAndRound> for Vec<u8> {
    fn from(value: HeightAndRound) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.put_u64(value.height);
        bytes.put_u32(value.round);
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
        Ok(HeightAndRound { height, round })
    }
}

impl std::fmt::Display for HeightAndRound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}:{})", self.height, self.round)
    }
}
