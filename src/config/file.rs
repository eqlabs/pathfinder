//! TOML configuration file parsing
use crate::config::{
    builder::ConfigBuilder,
    value::{IpAddrAsString, UrlAsString},
};
use reqwest::Url;
use serde::Deserialize;
use std::{net::IpAddr, path::PathBuf, str::FromStr};

lazy_static::lazy_static! {
    pub static ref DEFAULT_FILEPATH: PathBuf = home::home_dir()
            .unwrap_or_else(|| PathBuf::from_str("~/").unwrap())
            .join(".starknet")
            .join("config.toml");
}

#[serde_with::serde_as]
#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct EthereumConfig {
    #[serde(default)]
    #[serde_as(as = "Option<UrlAsString>")]
    url: Option<Url>,
    user: Option<String>,
    password: Option<String>,
}

#[serde_with::serde_as]
#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct HttpRpcConfig {
    enable: Option<bool>,
    #[serde(default)]
    #[serde_as(as = "Option<IpAddrAsString>")]
    address: Option<IpAddr>,
    port: Option<u16>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    ethereum: Option<EthereumConfig>,
    #[serde(rename = "http-rpc")]
    http_rpc: Option<HttpRpcConfig>,
}

impl FileConfig {
    /// Consumes a [FileConfig] to produce a [ConfigBuilder].
    fn into_config_options(self) -> ConfigBuilder {
        use crate::config::ConfigOption;
        let builder = match self.ethereum {
            Some(eth) => ConfigBuilder::default()
                .with(ConfigOption::EthereumUrl, eth.url)
                .with(ConfigOption::EthereumUser, eth.user)
                .with(ConfigOption::EthereumPassword, eth.password),
            None => ConfigBuilder::default(),
        };

        match self.http_rpc {
            Some(http) => builder
                .with(ConfigOption::HttpRpcEnable, http.enable)
                .with(ConfigOption::HttpRpcAddress, http.address)
                .with(ConfigOption::HttpRpcPort, http.port),
            None => builder,
        }
    }
}

/// Parses a [ConfigBuilder] from a toml format file.
pub fn config_from_filepath(filepath: &std::path::Path) -> std::io::Result<ConfigBuilder> {
    let file_contents = std::fs::read_to_string(filepath)?;
    config_from_str(&file_contents)
}

/// Parses a [ConfigBuilder] from a toml format file at `~/.starknet/config.toml` (see [DEFAULT_FILEPATH](static@DEFAULT_FILEPATH)).
pub fn config_from_default_filepath() -> std::io::Result<ConfigBuilder> {
    config_from_filepath(&DEFAULT_FILEPATH)
}

/// Deserializes a [ConfigBuilder] from a toml formatted str.
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
        let value = "http://localhost";
        let toml = format!(r#"ethereum.url = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumUrl)
                .expect("Take works"),
            Some(Url::from_str(value).expect("Valid URL"))
        );
    }

    #[test]
    fn ethereum_user() {
        let value = "value";
        let toml = format!(r#"ethereum.user = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumUser)
                .expect("Take works"),
            Some(value.to_owned())
        );
    }

    #[test]
    fn ethereum_password() {
        let value = "value";
        let toml = format!(r#"ethereum.password = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumPassword)
                .expect("Take works"),
            Some(value.to_owned())
        );
    }

    #[test]
    fn ethereum_section() {
        let user = "user".to_owned();
        let url = "http://localhost";
        let password = "password".to_owned();

        let toml = format!(
            r#"[ethereum]
    user = "{}"
    url = "{}"
    password = "{}""#,
            user, url, password
        );

        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumUser)
                .expect("Take works"),
            Some(user)
        );
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumUrl)
                .expect("Take works"),
            Some(Url::from_str(url).expect("Valid URL"))
        );
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumPassword)
                .expect("Take works"),
            Some(password)
        );
    }

    #[test]
    fn http_rpc_addr() {
        let value = "127.0.0.1";
        let toml = format!(r#"http-rpc.address = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcAddress)
                .expect("Take works"),
            Some(IpAddr::from_str(value).expect("Valid IP"))
        );
    }

    #[test]
    fn http_rpc_port() {
        let value = 1234_u16;
        let toml = format!(r#"http-rpc.port = {}"#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcPort)
                .expect("Take works"),
            Some(value)
        );
    }

    #[test]
    fn http_rpc_enable() {
        let value = true;
        let toml = format!(r#"http-rpc.enable = {}"#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcEnable)
                .expect("Take works"),
            Some(value)
        );
    }

    #[test]
    fn http_rpc_section() {
        let enable = true;
        let address = "127.0.0.1";
        let port = 1234_u16;

        let toml = format!(
            r#"[http-rpc]
    enable = {}
    address = "{}"
    port = {}"#,
            enable, address, port
        );

        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcEnable)
                .expect("Take works"),
            Some(enable)
        );
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcAddress)
                .expect("Take works"),
            Some(IpAddr::from_str(address).expect("Valid IP"))
        );
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcPort)
                .expect("Take works"),
            Some(port)
        );
    }

    #[test]
    fn empty_config() {
        let cfg = config_from_str("").unwrap();
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
