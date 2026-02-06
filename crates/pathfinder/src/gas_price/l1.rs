//! L1 Gas Price Provider
//!
//! Maintains a rolling buffer of L1 gas prices and computes rolling averages
//! for validating consensus proposals.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use pathfinder_common::L1BlockNumber;
use pathfinder_ethereum::L1GasPriceData;

use super::deviation_pct;
use crate::config::ConsensusConfig;

/// Configuration for L1 gas price validation.
#[derive(Debug, Clone)]
pub struct L1GasPriceConfig {
    /// Maximum number of samples to store in the buffer.
    /// Default: 1000 (~3.5 hours of blocks at 12s/block)
    pub storage_limit: usize,

    /// Number of blocks to use for computing the rolling average.
    /// Default: 100 (~20 minutes of blocks)
    pub blocks_for_mean: usize,

    /// Lag margin in seconds. When computing the rolling average for a given
    /// timestamp, we look back by this amount to account for network delays.
    /// Default: 300 (5 minutes)
    pub lag_margin_seconds: u64,

    /// Maximum allowed time gap between the requested timestamp and the latest
    /// sample. If exceeded, the data is considered stale.
    /// Default: 600 (10 minutes)
    pub max_time_gap_seconds: u64,

    /// Tolerance for price deviation (as a fraction, e.g., 0.20 for 20%).
    /// Default: 0.20 (20%)
    pub tolerance: f64,
}

impl Default for L1GasPriceConfig {
    fn default() -> Self {
        Self {
            storage_limit: 1000,
            blocks_for_mean: 100,
            lag_margin_seconds: 300,
            max_time_gap_seconds: 600,
            tolerance: 0.20,
        }
    }
}

impl From<&ConsensusConfig> for L1GasPriceConfig {
    #[cfg(feature = "p2p")]
    fn from(cfg: &ConsensusConfig) -> Self {
        L1GasPriceConfig {
            tolerance: cfg.l1_gas_price_tolerance,
            max_time_gap_seconds: cfg.l1_gas_price_max_time_gap,
            ..Default::default()
        }
    }
    #[cfg(not(feature = "p2p"))]
    fn from(_cfg: &ConsensusConfig) -> Self {
        L1GasPriceConfig::default()
    }
}

/// Error type for L1 gas price validation failures.
#[derive(Debug, thiserror::Error)]
pub enum L1GasPriceValidationError {
    #[error(
        "Base fee {proposed} deviates from expected {expected} by {deviation_pct:.2}% (max \
         allowed: {tolerance_pct:.2}%)"
    )]
    BaseFeeDeviation {
        proposed: u128,
        expected: u128,
        deviation_pct: f64,
        tolerance_pct: f64,
    },

    #[error(
        "Blob fee {proposed} deviates from expected {expected} by {deviation_pct:.2}% (max \
         allowed: {tolerance_pct:.2}%)"
    )]
    BlobFeeDeviation {
        proposed: u128,
        expected: u128,
        deviation_pct: f64,
        tolerance_pct: f64,
    },

    #[error(
        "L1 gas price data is stale: latest timestamp {latest_timestamp}, requested \
         {requested_timestamp} (max gap: {max_gap}s)"
    )]
    StaleData {
        latest_timestamp: u64,
        requested_timestamp: u64,
        max_gap: u64,
    },

    #[error("No gas price data available for timestamp {timestamp} with lag {lag_seconds}s")]
    NoDataAvailable { timestamp: u64, lag_seconds: u64 },
}

/// Result of validating L1 gas prices in a proposal.
#[derive(Debug)]
pub enum L1GasPriceValidationResult {
    /// The proposed gas prices are within acceptable tolerance.
    Valid,
    /// The proposed gas prices are invalid.
    Invalid(L1GasPriceValidationError),
    /// Insufficient data to perform validation.
    InsufficientData,
}

/// Provides L1 gas price data and validation for consensus proposals.
///
/// Uses ring buffer to store historical gas price samples and computes rolling
/// averages for validation.
#[derive(Clone)]
pub struct L1GasPriceProvider {
    inner: Arc<L1GasPriceProviderInner>,
}

struct L1GasPriceProviderInner {
    buffer: RwLock<BTreeMap<L1BlockNumber, L1GasPriceData>>,
    config: L1GasPriceConfig,
}

impl std::fmt::Debug for L1GasPriceProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let buffer = self.inner.buffer.read().unwrap();
        f.debug_struct("L1GasPriceProvider")
            .field("sample_count", &buffer.len())
            .field("config", &self.inner.config)
            .finish()
    }
}

impl L1GasPriceProvider {
    /// Creates a new L1 gas price provider with the given configuration.
    pub fn new(config: L1GasPriceConfig) -> Self {
        Self {
            inner: Arc::new(L1GasPriceProviderInner {
                buffer: RwLock::new(BTreeMap::new()),
                config,
            }),
        }
    }

    /// Returns the number of samples currently stored.
    pub fn sample_count(&self) -> usize {
        self.inner.buffer.read().unwrap().len()
    }

    /// Returns whether there is enough data to perform validation.
    pub fn is_ready(&self) -> bool {
        self.sample_count() > 0
    }

    /// Returns the latest block number stored, if any.
    pub fn latest_block_number(&self) -> Option<L1BlockNumber> {
        self.inner
            .buffer
            .read()
            .unwrap()
            .last_key_value()
            .map(|pair| *pair.0)
    }

    /// Adds a new gas price sample to the buffer.
    pub fn add_sample(&self, data: L1GasPriceData) {
        let mut buffer = self.inner.buffer.write().unwrap();

        if buffer.len() >= self.inner.config.storage_limit {
            buffer.pop_first();
        }

        // If the samples repeat, use the newer one (this can actually
        // happen after reorg).
        buffer.insert(data.block_number, data);
    }

    /// Adds multiple samples in bulk (used in initialization)
    pub fn add_samples(&self, samples: Vec<L1GasPriceData>) {
        for sample in samples {
            self.add_sample(sample);
        }
    }

    /// Computes the rolling average of gas prices for the given timestamp.
    ///
    /// Returns (avg_base_fee, avg_blob_fee).
    pub fn get_average_prices(
        &self,
        timestamp: u64,
    ) -> Result<(u128, u128), L1GasPriceValidationError> {
        let buffer = self.inner.buffer.read().unwrap();

        if buffer.is_empty() {
            return Err(L1GasPriceValidationError::NoDataAvailable {
                timestamp,
                lag_seconds: self.inner.config.lag_margin_seconds,
            });
        }

        let latest = buffer.last_key_value().map(|pair| *pair.1).unwrap();

        if timestamp > latest.timestamp + self.inner.config.max_time_gap_seconds {
            return Err(L1GasPriceValidationError::StaleData {
                latest_timestamp: latest.timestamp,
                requested_timestamp: timestamp,
                max_gap: self.inner.config.max_time_gap_seconds,
            });
        }

        let target_timestamp = timestamp.saturating_sub(self.inner.config.lag_margin_seconds);

        // Find the blocks we want to use
        let good_samples: Vec<&L1GasPriceData> = buffer
            .iter()
            .map(|pair| pair.1)
            .filter(|value| value.timestamp <= target_timestamp)
            .collect();

        let last_index = good_samples.len();

        let first_index = last_index.saturating_sub(self.inner.config.blocks_for_mean);
        let actual_count = last_index - first_index;

        if actual_count == 0 {
            return Err(L1GasPriceValidationError::NoDataAvailable {
                timestamp,
                lag_seconds: self.inner.config.lag_margin_seconds,
            });
        }

        if actual_count < self.inner.config.blocks_for_mean {
            tracing::debug!(
                "Using {} blocks for average (configured: {})",
                actual_count,
                self.inner.config.blocks_for_mean
            );
        }

        let mut base_fee_sum: u128 = 0;
        let mut blob_fee_sum: u128 = 0;

        for data in good_samples.iter().skip(first_index) {
            base_fee_sum = base_fee_sum.saturating_add(data.base_fee_per_gas);
            blob_fee_sum = blob_fee_sum.saturating_add(data.blob_fee);
        }

        let avg_base_fee = base_fee_sum / actual_count as u128;
        let avg_blob_fee = blob_fee_sum / actual_count as u128;

        Ok((avg_base_fee, avg_blob_fee))
    }

    /// Validates proposed gas prices against the rolling average.
    pub fn validate(
        &self,
        timestamp: u64,
        proposed_base_fee: u128,
        proposed_blob_fee: u128,
    ) -> L1GasPriceValidationResult {
        if !self.is_ready() {
            return L1GasPriceValidationResult::InsufficientData;
        }

        let (avg_base_fee, avg_blob_fee) = match self.get_average_prices(timestamp) {
            Ok(prices) => prices,
            Err(e) => return L1GasPriceValidationResult::Invalid(e),
        };

        let base_fee_deviation = deviation_pct(proposed_base_fee, avg_base_fee);
        if base_fee_deviation > self.inner.config.tolerance {
            return L1GasPriceValidationResult::Invalid(
                L1GasPriceValidationError::BaseFeeDeviation {
                    proposed: proposed_base_fee,
                    expected: avg_base_fee,
                    deviation_pct: base_fee_deviation * 100.0,
                    tolerance_pct: self.inner.config.tolerance * 100.0,
                },
            );
        }

        let blob_fee_deviation = deviation_pct(proposed_blob_fee, avg_blob_fee);
        if blob_fee_deviation > self.inner.config.tolerance {
            return L1GasPriceValidationResult::Invalid(
                L1GasPriceValidationError::BlobFeeDeviation {
                    proposed: proposed_blob_fee,
                    expected: avg_blob_fee,
                    deviation_pct: blob_fee_deviation * 100.0,
                    tolerance_pct: self.inner.config.tolerance * 100.0,
                },
            );
        }

        L1GasPriceValidationResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(block_num: u64, timestamp: u64, base_fee: u128, blob_fee: u128) -> L1GasPriceData {
        L1GasPriceData {
            block_number: L1BlockNumber::new_or_panic(block_num),
            timestamp,
            base_fee_per_gas: base_fee,
            blob_fee,
        }
    }

    #[test]
    fn test_provider_sample_management() {
        let provider = L1GasPriceProvider::new(L1GasPriceConfig::default());
        assert!(!provider.is_ready());
        assert!(matches!(
            provider.validate(1000, 100, 100),
            L1GasPriceValidationResult::InsufficientData
        ));

        provider.add_sample(sample(100, 1000, 100, 10));
        provider.add_sample(sample(101, 1012, 110, 11));
        assert_eq!(provider.sample_count(), 2);

        provider.add_sample(sample(105, 1060, 150, 15));
        assert_eq!(provider.sample_count(), 3);
    }

    #[test]
    fn test_buffer_overflow() {
        let small_provider = L1GasPriceProvider::new(L1GasPriceConfig {
            storage_limit: 3,
            ..Default::default()
        });
        for i in 0..5 {
            small_provider.add_sample(sample(i, i * 12, 100, 10));
        }
        assert_eq!(small_provider.sample_count(), 3);
        assert_eq!(
            small_provider.latest_block_number(),
            Some(L1BlockNumber::new_or_panic(4))
        );
    }

    #[test]
    fn test_rolling_average_with_lag() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 2,
            lag_margin_seconds: 24,
            max_time_gap_seconds: 1000,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        provider.add_sample(sample(0, 100, 100, 10));
        provider.add_sample(sample(1, 112, 200, 20));
        provider.add_sample(sample(2, 124, 300, 30));
        provider.add_sample(sample(3, 136, 400, 40));

        let (avg_base, avg_blob) = provider.get_average_prices(136).unwrap();
        assert_eq!(avg_base, 150);
        assert_eq!(avg_blob, 15);
    }

    #[test]
    fn test_validation() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 3,
            lag_margin_seconds: 0,
            max_time_gap_seconds: 100,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        provider.add_sample(sample(0, 100, 100, 10));
        provider.add_sample(sample(1, 112, 100, 10));
        provider.add_sample(sample(2, 124, 100, 10));

        assert!(matches!(
            provider.validate(124, 100, 10),
            L1GasPriceValidationResult::Valid
        ));
        assert!(matches!(
            provider.validate(124, 115, 11),
            L1GasPriceValidationResult::Valid
        ));

        assert!(matches!(
            provider.validate(124, 130, 10),
            L1GasPriceValidationResult::Invalid(L1GasPriceValidationError::BaseFeeDeviation { .. })
        ));

        assert!(matches!(
            provider.validate(300, 100, 10),
            L1GasPriceValidationResult::Invalid(L1GasPriceValidationError::StaleData { .. })
        ));
    }
}
