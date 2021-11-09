mod core;
mod gps;

use anyhow::{Context, Result};
use web3::ethabi::LogParam;

pub use self::core::CoreContract;
pub use self::gps::*;

/// Utility function to retrieve a named parameter from a log.
///
/// Useful for parsing logs.
fn get_log_param(log: &web3::ethabi::Log, param: &str) -> Result<LogParam> {
    log.params
        .iter()
        .find(|p| p.name == param)
        .cloned()
        .with_context(|| format!("parameter {} not found", param))
}
