use pathfinder_crypto::Felt;
use primitive_types::H256;

use crate::macros;

/// An Ethereum block number.
#[derive(Copy, Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct L1BlockNumber(u64);

macros::fmt::thin_display!(L1BlockNumber);

macros::i64_backed_u64::new_get_partialeq!(L1BlockNumber);
macros::i64_backed_u64::serdes!(L1BlockNumber);

impl From<L1BlockNumber> for Felt {
    fn from(x: L1BlockNumber) -> Self {
        Felt::from(x.0)
    }
}

impl std::iter::Iterator for L1BlockNumber {
    type Item = L1BlockNumber;

    fn next(&mut self) -> Option<Self::Item> {
        Some(*self + 1)
    }
}

impl L1BlockNumber {
    pub const GENESIS: L1BlockNumber = L1BlockNumber::new_or_panic(0);
}

impl std::ops::Add<u64> for L1BlockNumber {
    type Output = L1BlockNumber;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl std::ops::AddAssign<u64> for L1BlockNumber {
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl std::ops::Sub<u64> for L1BlockNumber {
    type Output = L1BlockNumber;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl std::ops::SubAssign<u64> for L1BlockNumber {
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

/// An Ethereum transaction hash.
pub type L1TransactionHash = H256;
