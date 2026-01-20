//! ETH to FRI (STRK) Oracle
//!
//! Converts L1 gas prices from Wei to FRI for consensus validation.
//!
//! - **Wei**: Smallest ETH unit (1 ETH = 10^18 Wei)
//! - **FRI**: Smallest STRK unit (1 STRK = 10^18 FRI)

use std::sync::Arc;

/// Error types for oracle operations.
#[derive(Debug, thiserror::Error)]
pub enum EthToFriOracleError {
    #[error("Conversion unavailable for timestamp {timestamp}")]
    Unavailable { timestamp: u64 },

    #[error("Oracle query failed: {0}")]
    QueryFailed(String),
}

/// Converts Wei amounts to FRI using current ETH/STRK exchange rate.
#[cfg_attr(test, mockall::automock)]
pub trait EthToFriOracle: Send + Sync {
    fn wei_to_fri(&self, wei: u128, timestamp: u64) -> Result<u128, EthToFriOracleError>;
}

impl<T: EthToFriOracle + ?Sized> EthToFriOracle for Arc<T> {
    fn wei_to_fri(&self, wei: u128, timestamp: u64) -> Result<u128, EthToFriOracleError> {
        self.as_ref().wei_to_fri(wei, timestamp)
    }
}
