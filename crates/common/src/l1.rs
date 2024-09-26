use pathfinder_crypto::Felt;
use primitive_types::H256;

use crate::macros;

/// An Ethereum block number.
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct L1BlockNumber(u64);

macros::fmt::thin_display!(L1BlockNumber);
macros::fmt::thin_debug!(L1BlockNumber);

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
#[derive(Copy, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct L1TransactionHash(H256);

macros::fmt::thin_display!(L1TransactionHash);
macros::fmt::thin_debug!(L1TransactionHash);

impl L1TransactionHash {
    /// Creates a new `L1TransactionHash` from a `H256`.
    pub fn new(hash: H256) -> Self {
        Self(hash)
    }

    /// Returns the raw bytes of the transaction hash.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Creates a new `L1TransactionHash` from a slice of bytes.
    ///
    /// # Panics
    ///
    /// If the length of the byte slice is not 32.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(H256::from_slice(bytes))
    }
}

impl From<H256> for L1TransactionHash {
    fn from(hash: H256) -> Self {
        Self(hash)
    }
}

impl From<L1TransactionHash> for H256 {
    fn from(tx_hash: L1TransactionHash) -> Self {
        tx_hash.0
    }
}

impl From<[u8; 32]> for L1TransactionHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(H256::from(bytes))
    }
}

impl AsRef<[u8]> for L1TransactionHash {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
