//! TOML configuration file parsing
use std::{path::PathBuf, str::FromStr};

use serde::Deserialize;

use crate::config::builder::ConfigBuilder;

lazy_static::lazy_static! {
    pub static ref DEFAULT_FILEPATH: PathBuf = home::home_dir()
            .unwrap_or_else(|| PathBuf::from_str("~/").unwrap())
            .join(".starknet")
            .join("config.toml");
}

#[derive(Deserialize, Debug, PartialEq)]
struct EthereumConfig {
    url: Option<String>,
    user: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct FileConfig {
    ethereum: Option<EthereumConfig>,
}

impl FileConfig {
    fn into_config_options(self) -> ConfigBuilder {
        use crate::config::ConfigOption;
        match self.ethereum {
            Some(eth) => ConfigBuilder::default()
                .with(ConfigOption::EthereumUrl, eth.url)
                .with(ConfigOption::EthereumUser, eth.user),
            None => ConfigBuilder::default(),
        }
    }
}

pub fn config_from_filepath(filepath: &std::path::Path) -> std::io::Result<ConfigBuilder> {
    let file_contents = std::fs::read_to_string(filepath)?;
    config_from_str(&file_contents)
}

pub fn config_from_default_filepath() -> std::io::Result<ConfigBuilder> {
    config_from_filepath(&DEFAULT_FILEPATH)
}

fn config_from_str(s: &str) -> std::io::Result<ConfigBuilder> {
    toml::from_str::<FileConfig>(s)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
        .map(|cfg| cfg.into_config_options())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigOption;

    #[test]
    fn ethereum_url() {
        let value = "value".to_owned();
        let toml = format!(r#"ethereum.url = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUrl), Some(value));
    }

    #[test]
    fn ethereum_user() {
        let value = "value".to_owned();
        let toml = format!(r#"ethereum.user = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUser), Some(value));
    }

    #[test]
    fn ethereum_section() {
        let user = "user".to_owned();
        let url = "url".to_owned();

        let toml = format!(
            r#"[ethereum]
user = "{}"
url = "{}""#,
            user, url
        );

        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUser), Some(user));
        assert_eq!(cfg.take(ConfigOption::EthereumUrl), Some(url));
    }

    #[test]
    fn empty_config() {
        let cfg = config_from_str("").unwrap();
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
