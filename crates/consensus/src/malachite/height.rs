/// A block number for the malachite context.
///
/// This is a wrapper around the `BlockNumber` type from the `pathfinder_common`
/// crate which implements the `Height` trait for the malachite context.
#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Copy, Debug, Default, Hash)]
pub struct Height(pathfinder_common::BlockNumber);

impl Height {
    pub fn new(block_number: u64) -> Self {
        Self(pathfinder_common::BlockNumber::new(block_number).expect("block number out of range"))
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

impl std::fmt::Display for Height {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
