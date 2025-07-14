use pathfinder_common::BlockNumber;
use serde::{Deserialize, Serialize};

/// The height of a block in the consensus protocol.
///
/// Used to identify the block being agreed upon by consensus. Each successful
/// consensus agreement produces a block and increments the height by one.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Default, Hash, Serialize, Deserialize)]
pub struct Height(pathfinder_common::BlockNumber);

impl Height {
    pub fn new(block_number: BlockNumber) -> Self {
        Self(block_number)
    }

    pub fn into_inner(&self) -> pathfinder_common::BlockNumber {
        self.0
    }

    pub fn as_inner(&self) -> &pathfinder_common::BlockNumber {
        &self.0
    }
}

impl TryFrom<u64> for Height {
    type Error = &'static str;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        pathfinder_common::BlockNumber::new(value)
            .map(Self)
            .ok_or("block number out of range")
    }
}

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Debug for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl malachite_types::Height for Height {
    const ZERO: Self = Self(pathfinder_common::BlockNumber::GENESIS);

    const INITIAL: Self = Self(pathfinder_common::BlockNumber::GENESIS);

    fn increment_by(&self, n: u64) -> Self {
        Self(self.0 + n)
    }

    fn decrement_by(&self, n: u64) -> Option<Self> {
        self.0.checked_sub(n).map(Self)
    }

    fn as_u64(&self) -> u64 {
        self.0.get()
    }

    fn increment(&self) -> Self {
        Self(self.0 + 1)
    }

    fn decrement(&self) -> Option<Self> {
        self.0.checked_sub(1).map(Self)
    }
}
