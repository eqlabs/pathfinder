//! L2 Gas Price Validation
//!
//! Implements Starknet's L2 gas price adjustment formula, which is inspired by
//! EIP-1559 but includes Starknet-specific behavior. The formula is ported
//! from Apollo's `fee_market` module.

use std::cmp::{max, min};
use std::sync::{Arc, RwLock};

use pathfinder_common::StarknetVersion;

/// Protocol constants for the L2 gas price adjustment formula.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2GasPriceConstants {
    pub gas_price_max_change_denominator: u128,
    pub gas_target: u128,
    pub max_block_size: u128,
    pub min_gas_price: u128,
}

impl L2GasPriceConstants {
    /// L2 gas price constants for Starknet versions before v0.14.1.
    const PRE_0_14_1: Self = Self {
        gas_price_max_change_denominator: 48,
        gas_target: 3_200_000_000,
        max_block_size: 4_000_000_000,
        min_gas_price: 3_000_000_000,
    };

    /// L2 gas price constants for Starknet v0.14.1 and later.
    const POST_0_14_1: Self = Self {
        gas_price_max_change_denominator: 48,
        gas_target: 4_000_000_000,
        max_block_size: 5_000_000_000,
        min_gas_price: 8_000_000_000,
    };

    /// Returns the L2 gas price constants for the given Starknet version.
    pub fn for_version(version: StarknetVersion) -> Self {
        if version >= StarknetVersion::V_0_14_1 {
            Self::POST_0_14_1
        } else {
            Self::PRE_0_14_1
        }
    }
}

/// Denominator for the maximum gas price increase per block when price is below
/// the minimum. Each block can increase by at most 1/333 (~0.3%) of the current
/// price.
const MIN_GAS_PRICE_INCREASE_DENOMINATOR: u128 = 333;

/// Calculate the base gas price for the next block using Starknet's
/// EIP-1559-inspired adjustment formula.
///
/// The `min_gas_price` parameter is separate from `constants` because Apollo
/// supports height-based min price overrides. For now we use the versioned
/// constant, but the signature allows future extension.
pub fn calculate_next_base_gas_price(
    price: u128,
    gas_used: u128,
    min_gas_price: u128,
    constants: &L2GasPriceConstants,
) -> u128 {
    // If the current price is below the minimum, apply a gradual adjustment.
    // Increases by at most 1/333 per block, capped at min_gas_price.
    if price < min_gas_price {
        let max_increase = price / MIN_GAS_PRICE_INCREASE_DENOMINATOR;
        let adjusted = price + max_increase;
        return min(adjusted, min_gas_price);
    }

    let gas_target = constants.gas_target;
    let gas_delta = gas_used.abs_diff(gas_target);

    // price * gas_delta fits in u128 for realistic values
    // (price ~10^10, gas_delta ~5*10^9, product ~5*10^19).
    let numerator = match price.checked_mul(gas_delta) {
        Some(n) => n,
        None => {
            // Fallback for extreme values: apply maximum possible change.
            // Note: Apollo uses U256 to avoid this entirely; for u128 this
            // will only trigger with super large prices (>~10^28).
            if gas_used > gas_target {
                return price.saturating_add(price / constants.gas_price_max_change_denominator);
            } else {
                let max_decrease = price / constants.gas_price_max_change_denominator;
                return max(price.saturating_sub(max_decrease), min_gas_price);
            }
        }
    };

    let denominator = gas_target * constants.gas_price_max_change_denominator;
    let price_change = numerator / denominator;

    let adjusted = if gas_used > gas_target {
        price + price_change
    } else {
        price - price_change
    };

    max(adjusted, min_gas_price)
}

/// Result of validating an L2 gas price proposal.
#[derive(Debug, PartialEq, Eq)]
pub enum L2GasPriceValidationResult {
    Valid,
    Invalid { proposed: u128, expected: u128 },
    InsufficientData,
}

/// Tracks the expected L2 gas price for the next block.
#[derive(Clone, Debug)]
pub struct L2GasPriceProvider {
    inner: Arc<RwLock<Option<u128>>>,
}

impl Default for L2GasPriceProvider {
    fn default() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }
}

impl L2GasPriceProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// Compute and store the expected L2 gas price for the next block, given
    /// the current block's price and gas consumption.
    pub fn update_after_block(
        &self,
        l2_gas_price_fri: u128,
        l2_gas_consumed: u128,
        constants: &L2GasPriceConstants,
    ) {
        let next_price = calculate_next_base_gas_price(
            l2_gas_price_fri,
            l2_gas_consumed,
            constants.min_gas_price,
            constants,
        );
        let mut state = self.inner.write().unwrap();
        *state = Some(next_price);
    }

    /// Validate a proposed L2 gas price against the expected value.
    pub fn validate(&self, proposed: u128) -> L2GasPriceValidationResult {
        let state = self.inner.read().unwrap();
        match *state {
            None => L2GasPriceValidationResult::InsufficientData,
            Some(expected) if proposed == expected => L2GasPriceValidationResult::Valid,
            Some(expected) => L2GasPriceValidationResult::Invalid { proposed, expected },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::Context;
    use rstest::rstest;
    use serde::Deserialize;

    use super::*;

    const TEST_PRICE: u128 = 30_000_000_000;

    /// Apollo versioned constants as they are defined in the
    /// `apollo_consensus_orchestrator` crate.
    #[derive(Debug, Deserialize)]
    struct ApolloVersionedConstants {
        gas_price_max_change_denominator: u128,
        gas_target: starknet_api::execution_resources::GasAmount,
        max_block_size: starknet_api::execution_resources::GasAmount,
        min_gas_price: starknet_api::block::GasPrice,
    }

    #[rstest]
    #[case::v0_13_2(StarknetVersion::V_0_13_2)]
    #[case::v0_13_4(StarknetVersion::V_0_13_4)]
    #[case::v0_14_0(StarknetVersion::V_0_14_0)]
    #[case::v0_14_1(StarknetVersion::V_0_14_1)]
    #[tokio::test]
    async fn l2_gas_constants_match_with_apollo(#[case] version: StarknetVersion) {
        let pathfinder_c = L2GasPriceConstants::for_version(version);
        let blockifier_tag = blockifier_tag_from_manifest().unwrap();
        let apollo_c = fetch_apollo_constants_for(version, blockifier_tag)
            .await
            .unwrap();

        assert_eq!(
            pathfinder_c.gas_price_max_change_denominator,
            apollo_c.gas_price_max_change_denominator
        );
        assert_eq!(pathfinder_c.gas_target, apollo_c.gas_target.0 as u128);
        assert_eq!(
            pathfinder_c.max_block_size,
            apollo_c.max_block_size.0 as u128
        );
        assert_eq!(pathfinder_c.min_gas_price, apollo_c.min_gas_price.0);
    }

    // Parses the workspace Cargo.toml to find the version of blockifier, which is
    // then used to construct the blockier tag in the form of
    // `blockifier-v{version-from-workspace-Cargo-toml}`.
    fn blockifier_tag_from_manifest() -> anyhow::Result<String> {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("Cargo.toml");
        let manifest = cargo_toml::Manifest::from_path(manifest_path)
            .context("loading workspace Cargo.toml")?;
        let workspace = manifest
            .workspace
            .context("getting workspace dependencies")?;
        let blockifier_version = workspace
            .dependencies
            .get("blockifier")
            .and_then(|dep| dep.try_req().ok())
            .context("parsing blockifier version from Cargo.toml")?;
        let blockifier_tag = format!("blockifier-v{blockifier_version}");
        Ok(blockifier_tag)
    }

    async fn fetch_apollo_constants_for(
        version: StarknetVersion,
        blockifier_tag: impl AsRef<str>,
    ) -> anyhow::Result<ApolloVersionedConstants> {
        // Apollo's constants are only versioned starting from v0.14.0, so for older
        // versions (which are expected to be same as v0.14.0) we fetch the v0.14.0
        // constants.
        let version = if version < StarknetVersion::V_0_14_0 {
            StarknetVersion::V_0_14_0
        } else {
            version
        };

        let url = format!(
            "https://raw.githubusercontent.com/starkware-libs/sequencer/\
                refs/tags/{}/\
                crates/apollo_consensus_orchestrator/resources/orchestrator_versioned_constants_{}_{}_{}.json",
            blockifier_tag.as_ref(),
            version.major(),
            version.minor(),
            version.patch()
        );
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("building http client")?;
        let resp = client
            .get(url)
            .send()
            .await
            .context("fetching apollo constants")?;
        resp.error_for_status()
            .context("http get failed")?
            .json()
            .await
            .context("parsing apollo constants")
    }

    // Apollo test vectors (from fee_market/test.rs)

    #[test]
    fn high_congestion() {
        let c = L2GasPriceConstants::POST_0_14_1;
        let gas_used = c.max_block_size * 3 / 4;
        let gas_target = c.max_block_size / 2;
        let constants = L2GasPriceConstants { gas_target, ..c };
        let result =
            calculate_next_base_gas_price(TEST_PRICE, gas_used, c.min_gas_price, &constants);
        assert_eq!(result, 30_312_500_000);
    }

    #[test]
    fn low_congestion() {
        let c = L2GasPriceConstants::POST_0_14_1;
        let gas_used = c.max_block_size / 4;
        let gas_target = c.max_block_size / 2;
        let constants = L2GasPriceConstants { gas_target, ..c };
        let result =
            calculate_next_base_gas_price(TEST_PRICE, gas_used, c.min_gas_price, &constants);
        assert_eq!(result, 29_687_500_000);
    }

    #[test]
    fn gas_used_zero_max_decrease() {
        let c = L2GasPriceConstants::POST_0_14_1;
        let result = calculate_next_base_gas_price(TEST_PRICE, 0, c.min_gas_price, &c);
        let expected = TEST_PRICE - TEST_PRICE / 48;
        assert_eq!(result, expected);
    }

    #[test]
    fn floor_clamping() {
        let c = L2GasPriceConstants::POST_0_14_1;
        let price = c.min_gas_price + 1;
        let result = calculate_next_base_gas_price(price, 0, c.min_gas_price, &c);
        assert_eq!(result, c.min_gas_price);
    }

    #[test]
    fn overflow_does_not_panic() {
        let c = L2GasPriceConstants::POST_0_14_1;
        let gas_target = c.max_block_size / 2;
        let constants = L2GasPriceConstants { gas_target, ..c };
        let price = u64::MAX as u128;
        let _ = calculate_next_base_gas_price(price, 0, c.min_gas_price, &constants);
    }

    #[test]
    fn below_minimum_gradual_increase() {
        let min_gas_price = 20_000_000_000u128;
        let price = 10_000_000_000u128;
        let constants = L2GasPriceConstants {
            min_gas_price,
            ..L2GasPriceConstants::POST_0_14_1
        };
        let result = calculate_next_base_gas_price(price, 1000, min_gas_price, &constants);

        let max_increase = price / MIN_GAS_PRICE_INCREASE_DENOMINATOR;
        let expected = price + max_increase;
        assert_eq!(result, expected);
        assert!(result > price);
        assert!(result < min_gas_price);
    }

    #[test]
    fn below_minimum_caps_near_threshold() {
        let min_gas_price = 10_000_000_000u128;
        let price = 9_971_000_000u128;
        let constants = L2GasPriceConstants {
            min_gas_price,
            ..L2GasPriceConstants::POST_0_14_1
        };
        let result = calculate_next_base_gas_price(price, 1000, min_gas_price, &constants);
        assert_eq!(result, min_gas_price);
    }

    // After a block is finalized, the provider uses its price and gas
    // consumption to compute the expected price for the next block.
    // Validating a proposal with that exact price succeeds.
    #[test]
    fn provider_accepts_correct_price() {
        let provider = L2GasPriceProvider::new();
        let c = L2GasPriceConstants::POST_0_14_1;

        let block_gas_price = TEST_PRICE;
        let block_gas_consumed = c.gas_target; // at target → no change
        provider.update_after_block(block_gas_price, block_gas_consumed, &c);

        let next_block_proposed_price = TEST_PRICE;
        assert_eq!(
            provider.validate(next_block_proposed_price),
            L2GasPriceValidationResult::Valid
        );
    }

    // A proposal whose price doesn't match the expected value is rejected.
    #[test]
    fn provider_rejects_wrong_price() {
        let provider = L2GasPriceProvider::new();
        let c = L2GasPriceConstants::POST_0_14_1;

        let block_price = TEST_PRICE;
        let block_gas_consumed = c.gas_target;
        provider.update_after_block(block_price, block_gas_consumed, &c);

        let wrong_price = 999;
        assert_eq!(
            provider.validate(wrong_price),
            L2GasPriceValidationResult::Invalid {
                proposed: wrong_price,
                expected: TEST_PRICE,
            }
        );
    }

    // Before any block is processed the provider has no expected price, so
    // validation returns InsufficientData (allows proposals through during
    // cold start).
    #[test]
    fn provider_without_data_does_not_reject() {
        let provider = L2GasPriceProvider::new();
        assert_eq!(
            provider.validate(100),
            L2GasPriceValidationResult::InsufficientData
        );
    }
}
