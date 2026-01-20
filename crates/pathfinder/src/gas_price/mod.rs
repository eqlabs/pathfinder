//! Gas Price Validation
//!
//! This module provides gas price validation for consensus proposals

pub mod l1;

pub use l1::{
    L1GasPriceConfig,
    L1GasPriceProvider,
    L1GasPriceValidationError,
    L1GasPriceValidationResult,
};

/// Calculates the percentage deviation between two values.
/// Returns 0.0 for equal values, 0.10 for 10% deviation, etc.
pub(crate) fn deviation_pct(proposed: u128, expected: u128) -> f64 {
    match (expected, proposed) {
        (0, 0) => 0.0,
        (0, _) => f64::INFINITY,
        _ => (proposed as f64 - expected as f64).abs() / expected as f64,
    }
}
