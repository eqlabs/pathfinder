//! TOML configuration file parsing
use std::{path::PathBuf, str::FromStr};

use serde::Deserialize;

lazy_static::lazy_static! {
    pub static ref DEFAULT_FILEPATH: PathBuf = home::home_dir()
            .unwrap_or_else(|| PathBuf::from_str("~/").unwrap())
            .join(".starknet")
            .join("config.toml");
}

/// Supported config file options.
#[derive(Deserialize, Debug, PartialEq)]
pub struct FileConfig {
    /// The Ethereum RPC endpoint.
    pub ethereum_rpc_url: Option<String>,
}

impl FileConfig {
    /// Parses the file and returns the node configuration options. File must be a TOML file.
    pub fn from_filepath(filepath: &std::path::Path) -> std::io::Result<Self> {
        let file_contents = std::fs::read_to_string(filepath)?;
        Self::from_str(&file_contents)
    }

    /// Parses the file at the [default filepath](static@DEFAULT_FILEPATH).
    pub fn from_default_filepath() -> std::io::Result<Self> {
        Self::from_filepath(&DEFAULT_FILEPATH)
    }

    /// Parses the given string.
    fn from_str(s: &str) -> std::io::Result<Self> {
        toml::from_str::<Self>(s)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_endpoint() {
        let value = "value".to_owned();
        let toml = format!(r#"ethereum_rpc_url = "{}""#, value);
        let cfg = FileConfig::from_str(&toml).unwrap();
        assert_eq!(cfg.ethereum_rpc_url, Some(value));
    }

    #[test]
    fn empty_config() {
        let cfg = FileConfig::from_str("").unwrap();
        assert_eq!(
            cfg,
            FileConfig {
                ethereum_rpc_url: None,
            }
        );
    }
}
