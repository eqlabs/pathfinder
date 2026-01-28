//! L1 to FRI Conversion Validation
//!
//! Validates that L1 gas prices converted to FRI are consistent between
//! proposer and validator.

use std::sync::Arc;

use super::l1::L1GasPriceProvider;
use super::oracle::EthToFriOracle;
use super::{deviation_pct, ETH_TO_WEI};

/// Configuration for L1-to-FRI price validation.
#[derive(Debug, Clone)]
pub struct L1ToFriValidationConfig {
    /// Maximum allowed deviation between validator's and proposer's FRI prices.
    /// Default: 0.10 (10%)
    pub max_fri_deviation: f64,
}

impl Default for L1ToFriValidationConfig {
    fn default() -> Self {
        Self {
            max_fri_deviation: 0.10,
        }
    }
}

/// Result of L1-to-FRI price validation.
#[derive(Debug)]
pub enum L1ToFriValidationResult {
    /// Prices are within acceptable margin.
    Valid,
    /// FRI price deviation exceeds tolerance.
    InvalidFriDeviation {
        proposed_fri: u128,
        expected_fri: u128,
        deviation_pct: f64,
    },
    /// Insufficient data to perform validation.
    InsufficientData,
}

/// Validates L1 gas prices converted to FRI.
///
/// Compares proposer's FRI prices against validator's independently computed
/// FRI prices. Allows up to 10% deviation to account for timing differences
/// in rate fetching.
pub struct L1ToFriValidator {
    oracle: Arc<dyn EthToFriOracle>,
    l1_gas_provider: L1GasPriceProvider,
    config: L1ToFriValidationConfig,
}

impl L1ToFriValidator {
    pub fn new(
        oracle: Arc<dyn EthToFriOracle>,
        l1_gas_provider: L1GasPriceProvider,
        config: L1ToFriValidationConfig,
    ) -> Self {
        Self {
            oracle,
            l1_gas_provider,
            config,
        }
    }

    /// Validates L1 gas prices in FRI terms.
    ///
    /// Proposer provides their Wei prices and their ETH/FRI rate.
    /// Validator independently fetches Wei prices and uses oracle for
    /// conversion. If the resulting FRI prices differ by more than 10%,
    /// validation fails.
    pub fn validate(
        &self,
        timestamp: u64,
        proposed_l1_gas_price_wei: u128,
        proposed_l1_data_gas_price_wei: u128,
        proposed_eth_to_fri_rate: u128,
    ) -> L1ToFriValidationResult {
        let (validator_base_fee_wei, validator_blob_fee_wei) =
            match self.l1_gas_provider.get_average_prices(timestamp) {
                Ok(prices) => prices,
                Err(e) => {
                    tracing::debug!(timestamp, error = %e, "L1-to-FRI: no L1 gas price data");
                    return L1ToFriValidationResult::InsufficientData;
                }
            };

        let validator_base_fee_fri = match self.oracle.wei_to_fri(validator_base_fee_wei, timestamp)
        {
            Ok(fri) => fri,
            Err(e) => {
                tracing::debug!(timestamp, error = %e, "L1-to-FRI: oracle unavailable");
                return L1ToFriValidationResult::InsufficientData;
            }
        };
        let validator_blob_fee_fri = match self.oracle.wei_to_fri(validator_blob_fee_wei, timestamp)
        {
            Ok(fri) => fri,
            Err(e) => {
                tracing::debug!(timestamp, error = %e, "L1-to-FRI: oracle unavailable");
                return L1ToFriValidationResult::InsufficientData;
            }
        };

        // Compute proposer's FRI using their rate: fri = wei * rate / 10^18
        let proposer_base_fee_fri =
            proposed_l1_gas_price_wei.saturating_mul(proposed_eth_to_fri_rate) / ETH_TO_WEI;
        let proposer_blob_fee_fri =
            proposed_l1_data_gas_price_wei.saturating_mul(proposed_eth_to_fri_rate) / ETH_TO_WEI;

        let base_deviation = deviation_pct(proposer_base_fee_fri, validator_base_fee_fri);
        if base_deviation > self.config.max_fri_deviation {
            tracing::debug!(
                proposer_base_fee_fri,
                validator_base_fee_fri,
                deviation_pct = base_deviation * 100.0,
                "L1-to-FRI base fee deviation exceeds tolerance"
            );
            return L1ToFriValidationResult::InvalidFriDeviation {
                proposed_fri: proposer_base_fee_fri,
                expected_fri: validator_base_fee_fri,
                deviation_pct: base_deviation * 100.0,
            };
        }

        let blob_deviation = deviation_pct(proposer_blob_fee_fri, validator_blob_fee_fri);
        if blob_deviation > self.config.max_fri_deviation {
            tracing::debug!(
                proposer_blob_fee_fri,
                validator_blob_fee_fri,
                deviation_pct = blob_deviation * 100.0,
                "L1-to-FRI blob fee deviation exceeds tolerance"
            );
            return L1ToFriValidationResult::InvalidFriDeviation {
                proposed_fri: proposer_blob_fee_fri,
                expected_fri: validator_blob_fee_fri,
                deviation_pct: blob_deviation * 100.0,
            };
        }

        L1ToFriValidationResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use pathfinder_common::L1BlockNumber;
    use pathfinder_ethereum::L1GasPriceData;

    use super::*;
    use crate::gas_price::l1::L1GasPriceConfig;
    use crate::gas_price::oracle::MockEthToFriOracle;

    fn sample(block_num: u64, timestamp: u64, base_fee: u128, blob_fee: u128) -> L1GasPriceData {
        L1GasPriceData {
            block_number: L1BlockNumber::new_or_panic(block_num),
            timestamp,
            base_fee_per_gas: base_fee,
            blob_fee,
        }
    }

    fn make_provider_with_samples() -> L1GasPriceProvider {
        let config = L1GasPriceConfig {
            storage_limit: 100,
            blocks_for_mean: 3,
            lag_margin_seconds: 0,
            max_time_gap_seconds: 1000,
            tolerance: 0.20,
        };
        let provider = L1GasPriceProvider::new(config);
        provider.add_sample(sample(0, 100, 1000, 100));
        provider.add_sample(sample(1, 112, 1000, 100));
        provider.add_sample(sample(2, 124, 1000, 100));
        provider
    }

    #[test]
    fn test_fri_validation_valid_cases() {
        let mut mock = MockEthToFriOracle::new();
        mock.expect_wei_to_fri().returning(|wei, _| Ok(wei * 2));
        let v = L1ToFriValidator::new(
            Arc::new(mock),
            make_provider_with_samples(),
            L1ToFriValidationConfig::default(),
        );

        let proposer_rate = 2 * ETH_TO_WEI;
        assert!(matches!(
            v.validate(124, 1000, 100, proposer_rate),
            L1ToFriValidationResult::Valid
        ));
    }

    #[test]
    fn test_fri_validation_error_cases() {
        let mut mock = MockEthToFriOracle::new();
        mock.expect_wei_to_fri().returning(|wei, _| Ok(wei * 2));
        let v = L1ToFriValidator::new(
            Arc::new(mock),
            make_provider_with_samples(),
            L1ToFriValidationConfig::default(),
        );

        let proposer_rate = 3 * ETH_TO_WEI;
        assert!(matches!(
            v.validate(124, 1000, 100, proposer_rate),
            L1ToFriValidationResult::InvalidFriDeviation { .. }
        ));

        let mut mock = MockEthToFriOracle::new();
        mock.expect_wei_to_fri().returning(|_, ts| {
            Err(crate::gas_price::oracle::EthToFriOracleError::Unavailable { timestamp: ts })
        });
        let v = L1ToFriValidator::new(
            Arc::new(mock),
            make_provider_with_samples(),
            L1ToFriValidationConfig::default(),
        );
        assert!(matches!(
            v.validate(124, 1000, 100, 2 * ETH_TO_WEI),
            L1ToFriValidationResult::InsufficientData
        ));
    }
}
