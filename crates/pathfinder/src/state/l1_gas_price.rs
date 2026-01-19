//! L1 Gas Price Provider
//!
//! This module provides gas price validation for consensus proposals by
//! maintaining a rolling buffer of L1 gas prices and computing rolling
//! averages.
//!
//! Heavily inspired by Apollo's `apollo_l1_gas_price` crate:
//! - Ring buffer stores historical gas price samples from L1 block headers
//! - Rolling average is computed over a configurable number of blocks
//! - A lag margin is applied to account for network propagation delays
//! - Proposed prices are validated against the rolling average with a tolerance

use std::collections::VecDeque;
use std::sync::{Arc, RwLock};

use pathfinder_common::L1BlockNumber;
use pathfinder_ethereum::L1GasPriceData;

/// Configuration for L1 gas price validation.
#[derive(Debug, Clone)]
pub struct L1GasPriceConfig {
    /// Maximum number of samples to store in the ring buffer.
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
    /// Proposed prices within this deviation from the rolling average are
    /// valid. Default: 0.20 (20%)
    pub tolerance: f64,
}

impl Default for L1GasPriceConfig {
    fn default() -> Self {
        Self {
            storage_limit: 1000,
            blocks_for_mean: 100,
            lag_margin_seconds: 300,
            max_time_gap_seconds: 600 * 100, // TODO testing, reduce later
            tolerance: 1.20,                 // TODO testing, reduce later
        }
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
    buffer: RwLock<VecDeque<L1GasPriceData>>,
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
                buffer: RwLock::new(VecDeque::with_capacity(config.storage_limit)),
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
            .back()
            .map(|d| d.block_number)
    }

    /// Adds a new gas price sample to the buffer.
    ///
    /// Samples are expected to be added in sequential block order.
    ///
    /// Returns an error if the block number is not sequential.
    pub fn add_sample(&self, data: L1GasPriceData) -> Result<(), anyhow::Error> {
        let mut buffer = self.inner.buffer.write().unwrap();

        // Verify sequential block ordering
        if let Some(last) = buffer.back() {
            let expected = last.block_number.get() + 1;
            if data.block_number.get() != expected {
                anyhow::bail!(
                    "Non-sequential block: expected {}, got {}",
                    expected,
                    data.block_number.get()
                );
            }
        }

        // Remove oldest if at capacity
        if buffer.len() >= self.inner.config.storage_limit {
            buffer.pop_front();
        }

        buffer.push_back(data);
        Ok(())
    }

    /// Adds multiple samples in bulk (used in initialization)
    ///
    /// Note: must be sorted by block number in ascending order.
    pub fn add_samples(&self, samples: Vec<L1GasPriceData>) -> Result<(), anyhow::Error> {
        for sample in samples {
            self.add_sample(sample)?;
        }
        Ok(())
    }

    /// Computes the rolling average of gas prices for the given timestamp.
    ///
    /// The algorithm:
    /// 1. Apply lag margin to get the target timestamp
    /// 2. Find all blocks with timestamp <= target timestamp
    /// 3. Take the last `blocks_for_mean` blocks (or all if fewer available)
    /// 4. Compute the average of base_fee and blob_fee
    ///
    /// Returns (avg_base_fee, avg_blob_fee)
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

        let latest = buffer.back().unwrap();

        // Check for stale data
        if timestamp > latest.timestamp + self.inner.config.max_time_gap_seconds {
            return Err(L1GasPriceValidationError::StaleData {
                latest_timestamp: latest.timestamp,
                requested_timestamp: timestamp,
                max_gap: self.inner.config.max_time_gap_seconds,
            });
        }

        // Apply lag margin
        let target_timestamp = timestamp.saturating_sub(self.inner.config.lag_margin_seconds);

        // Find the last block with timestamp <= target_timestamp (searching backwards)
        let last_index = buffer
            .iter()
            .rposition(|data| data.timestamp <= target_timestamp);

        let last_index = match last_index {
            Some(idx) => idx + 1, // Convert to exclusive end index
            None => {
                return Err(L1GasPriceValidationError::NoDataAvailable {
                    timestamp,
                    lag_seconds: self.inner.config.lag_margin_seconds,
                });
            }
        };

        // Determine the first index for the rolling average
        let first_index = last_index.saturating_sub(self.inner.config.blocks_for_mean);
        let actual_count = last_index - first_index;

        if actual_count == 0 {
            return Err(L1GasPriceValidationError::NoDataAvailable {
                timestamp,
                lag_seconds: self.inner.config.lag_margin_seconds,
            });
        }

        // Log if using fewer blocks than configured
        if actual_count < self.inner.config.blocks_for_mean {
            tracing::debug!(
                "Using {} blocks for average (configured: {})",
                actual_count,
                self.inner.config.blocks_for_mean
            );
        }

        // Compute the sum
        let mut base_fee_sum: u128 = 0;
        let mut blob_fee_sum: u128 = 0;

        for data in buffer.range(first_index..last_index) {
            base_fee_sum = base_fee_sum.saturating_add(data.base_fee_per_gas);
            blob_fee_sum = blob_fee_sum.saturating_add(data.blob_fee);
        }

        // Compute the average
        let avg_base_fee = base_fee_sum / actual_count as u128;
        let avg_blob_fee = blob_fee_sum / actual_count as u128;

        Ok((avg_base_fee, avg_blob_fee))
    }

    /// Validates proposed gas prices against the rolling average.
    ///
    /// # Arguments
    /// * `timestamp` - The block timestamp from the proposal
    /// * `proposed_base_fee` - The proposed l1_gas_price_wei value
    /// * `proposed_blob_fee` - The proposed l1_data_gas_price_wei value
    ///
    /// # Returns
    /// * `Valid` - If prices are within tolerance
    /// * `Invalid` - If prices deviate too much from the expected values
    /// * `InsufficientData` - If there's not enough data to validate
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

        // Check base fee deviation
        let base_fee_deviation = deviation_pcnt(proposed_base_fee, avg_base_fee);
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

        // Check blob fee deviation
        let blob_fee_deviation = deviation_pcnt(proposed_blob_fee, avg_blob_fee);
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

/// Calculates the % deviation between proposed and expected.
fn deviation_pcnt(proposed: u128, expected: u128) -> f64 {
    match (expected, proposed) {
        (0, 0) => 0.0,
        (0, _) => f64::INFINITY,
        _ => {
            let proposed = proposed as f64;
            let expected = expected as f64;
            (proposed - expected).abs() / expected
        }
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
    fn test_deviation_pcnt() {
        assert!((deviation_pcnt(100, 100) - 0.0).abs() < 0.001);
        assert!((deviation_pcnt(110, 100) - 0.10).abs() < 0.001);
        assert!((deviation_pcnt(90, 100) - 0.10).abs() < 0.001);
        assert!((deviation_pcnt(120, 100) - 0.20).abs() < 0.001);
        assert!((deviation_pcnt(0, 0) - 0.0).abs() < 0.001);
        assert!(deviation_pcnt(100, 0).is_infinite());
    }

    #[test]
    fn test_empty_provider() {
        let provider = L1GasPriceProvider::new(L1GasPriceConfig::default());
        assert!(!provider.is_ready());
        assert_eq!(provider.sample_count(), 0);
        assert!(matches!(
            provider.validate(1000, 100, 100),
            L1GasPriceValidationResult::InsufficientData
        ));
    }

    #[test]
    fn test_add_sample_sequential() {
        let provider = L1GasPriceProvider::new(L1GasPriceConfig::default());

        provider.add_sample(sample(100, 1000, 100, 10)).unwrap();
        provider.add_sample(sample(101, 1012, 110, 11)).unwrap();
        provider.add_sample(sample(102, 1024, 120, 12)).unwrap();

        assert_eq!(provider.sample_count(), 3);
    }

    #[test]
    fn test_add_sample_non_sequential_fails() {
        let provider = L1GasPriceProvider::new(L1GasPriceConfig::default());

        provider.add_sample(sample(100, 1000, 100, 10)).unwrap();
        let result = provider.add_sample(sample(105, 1060, 150, 15));

        assert!(result.is_err());
    }

    #[test]
    fn test_ring_buffer_overflow() {
        let config = L1GasPriceConfig {
            storage_limit: 3,
            ..Default::default()
        };
        let provider = L1GasPriceProvider::new(config);

        // Add 5 samples to a buffer of size 3
        for i in 0..5 {
            provider
                .add_sample(sample(i, i * 12, 100 + i as u128, 10))
                .unwrap();
        }

        assert_eq!(provider.sample_count(), 3);
        // Should contain blocks 2, 3, 4
        assert_eq!(
            provider.latest_block_number(),
            Some(L1BlockNumber::new_or_panic(4))
        );
    }

    #[test]
    fn test_rolling_average() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 3,
            lag_margin_seconds: 0,
            max_time_gap_seconds: 1000,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        // Add samples with known values
        provider.add_sample(sample(0, 100, 100, 10)).unwrap();
        provider.add_sample(sample(1, 112, 200, 20)).unwrap();
        provider.add_sample(sample(2, 124, 300, 30)).unwrap();

        // Average of 100, 200, 300 = 200; Average of 10, 20, 30 = 20
        let (avg_base, avg_blob) = provider.get_average_prices(124).unwrap();
        assert_eq!(avg_base, 200);
        assert_eq!(avg_blob, 20);
    }

    #[test]
    fn test_rolling_average_with_lag_margin() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 2,
            lag_margin_seconds: 24, // 2 blocks worth of lag
            max_time_gap_seconds: 1000,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        // Add samples
        provider.add_sample(sample(0, 100, 100, 10)).unwrap();
        provider.add_sample(sample(1, 112, 200, 20)).unwrap();
        provider.add_sample(sample(2, 124, 300, 30)).unwrap();
        provider.add_sample(sample(3, 136, 400, 40)).unwrap();

        // Timestamp 136 with lag 24 = target timestamp 112
        // Should include blocks with timestamp <= 112, i.e., blocks 0 and 1
        // Average of 100, 200 = 150; Average of 10, 20 = 15
        let (avg_base, avg_blob) = provider.get_average_prices(136).unwrap();
        assert_eq!(avg_base, 150);
        assert_eq!(avg_blob, 15);
    }

    #[test]
    fn test_validation_valid() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 3,
            lag_margin_seconds: 0,
            max_time_gap_seconds: 1000,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        provider.add_sample(sample(0, 100, 100, 10)).unwrap();
        provider.add_sample(sample(1, 112, 100, 10)).unwrap();
        provider.add_sample(sample(2, 124, 100, 10)).unwrap();

        // Proposed values match exactly
        let result = provider.validate(124, 100, 10);
        assert!(matches!(result, L1GasPriceValidationResult::Valid));

        // Proposed values within 20% tolerance
        let result = provider.validate(124, 115, 11);
        assert!(matches!(result, L1GasPriceValidationResult::Valid));
    }

    #[test]
    fn test_validation_invalid_base_fee() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 3,
            lag_margin_seconds: 0,
            max_time_gap_seconds: 1000,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        provider.add_sample(sample(0, 100, 100, 10)).unwrap();
        provider.add_sample(sample(1, 112, 100, 10)).unwrap();
        provider.add_sample(sample(2, 124, 100, 10)).unwrap();

        // Proposed base fee is 30% higher (exceeds 20% tolerance)
        let result = provider.validate(124, 130, 10);
        assert!(matches!(
            result,
            L1GasPriceValidationResult::Invalid(L1GasPriceValidationError::BaseFeeDeviation { .. })
        ));
    }

    #[test]
    fn test_validation_stale_data() {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 3,
            lag_margin_seconds: 0,
            max_time_gap_seconds: 100,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);

        provider.add_sample(sample(0, 100, 100, 10)).unwrap();

        // Request with timestamp way beyond the max gap
        let result = provider.validate(300, 100, 10);
        assert!(matches!(
            result,
            L1GasPriceValidationResult::Invalid(L1GasPriceValidationError::StaleData { .. })
        ));
    }
}
