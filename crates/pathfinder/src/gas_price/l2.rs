//! L2 Gas Price Validation
//!
//! Implements Starknet's L2 gas price adjustment formula, which is inspired by
//! EIP-1559 but includes Starknet-specific behavior. The formula is ported
//! from Apollo's `fee_market` module.

use std::cmp::{max, min};

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
    /// Returns the L2 gas price constants for the given Starknet version.
    pub fn for_version(version: StarknetVersion) -> Self {
        // v0.14.1+ uses updated constants
        if version >= StarknetVersion::new(0, 14, 1, 0) {
            Self {
                gas_price_max_change_denominator: 48,
                gas_target: 4_000_000_000,
                max_block_size: 5_000_000_000,
                min_gas_price: 8_000_000_000,
            }
        } else {
            // v0.14.0
            Self {
                gas_price_max_change_denominator: 48,
                gas_target: 3_200_000_000,
                max_block_size: 4_000_000_000,
                min_gas_price: 3_000_000_000,
            }
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
