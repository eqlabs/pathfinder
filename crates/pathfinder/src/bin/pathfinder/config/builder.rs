//! Provides [ConfigBuilder] which is a convenient and safe way of collecting
//! configuration parameters from various sources and combining them into one.

use crate::config::{ConfigOption, Configuration, EthereumConfig};
use reqwest::Url;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};

/// A convenient way of collecting and merging configuration options.
///
/// Once finalised, can be converted to [Configuration] using `try_build`.
#[derive(Default, PartialEq, Eq, Debug)]
pub struct ConfigBuilder(HashMap<ConfigOption, String>);

impl ConfigBuilder {
    /// Sets the [ConfigOption] to value; if the value is [None] it gets removed.
    pub fn with(mut self, option: ConfigOption, value: Option<String>) -> Self {
        match value {
            Some(v) => self.0.insert(option, v),
            None => self.0.remove(&option),
        };
        self
    }

    /// Attempts to generate a [Configuration] from the options. Performs type checking
    /// and parsing as required by [Configuration] types. Also ensures that all
    /// required options are set.
    pub fn try_build(mut self) -> std::io::Result<Configuration> {
        use super::DEFAULT_HTTP_RPC_ADDR;

        // Required parameters.
        let eth_url = self.take_required(ConfigOption::EthereumHttpUrl)?;

        // this used to be the url in docker run example
        if eth_url == "https://goerli.infura.io/v3/<project-id>" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid Ethereum URL ({eth_url}): Cannot use the URL from examples!

Hint: Register your own account or run your own Ethereum node and put the real URL as the configuration value.")
            ));
        }

        // Parse the Ethereum URL.
        let eth_url = eth_url.parse::<Url>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid Ethereum URL ({eth_url}): {err}"),
            )
        })?;

        // Optional parameters.
        let eth_password = self.take(ConfigOption::EthereumPassword);

        let monitoring_addr = self
            .take(ConfigOption::MonitorAddress)
            .map(|addr| {
                addr.parse::<SocketAddr>().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid monitoring listening interface and port ({addr}): {err}"),
                    )
                })
            })
            .transpose()?;

        let network = self.take(ConfigOption::Network);

        let gateway = match self.take(ConfigOption::GatewayUrl) {
            Some(url) => {
                let url = url.parse::<Url>().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid StarkNet gateway URL ({url}): {err}"),
                    )
                })?;

                Some(url)
            }
            None => None,
        };
        let feeder = match self.take(ConfigOption::FeederGatewayUrl) {
            Some(url) => {
                let url = url.parse::<Url>().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid StarkNet feeder gateway URL ({url}): {err}"),
                    )
                })?;

                Some(url)
            }
            None => None,
        };
        let chain_id = self.take(ConfigOption::ChainId);

        let custom_gateway = match (gateway, feeder, chain_id) {
            (None, None, None) => None,
            (Some(gateway), Some(feeder), Some(chain_id)) => Some((gateway, feeder, chain_id)),
            (None, _, _) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing gateway URL configuration",
                ))
            }
            (_, None, _) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing feeder gateway URL configuration",
                ))
            }
            (_, _, None) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Missing chain ID configuration",
                ))
            }
        };

        // Optional parameters with defaults.
        let data_directory = self
            .take(ConfigOption::DataDirectory)
            .map(|s| Ok(PathBuf::from_str(&s).unwrap()))
            .unwrap_or_else(std::env::current_dir)?;
        let http_rpc_addr = self
            .take(ConfigOption::HttpRpcAddress)
            .unwrap_or_else(|| DEFAULT_HTTP_RPC_ADDR.to_owned());
        let python_subprocesses = match self.take(ConfigOption::PythonSubprocesses) {
            Some(python_subprocesses) => {
                let num: usize = python_subprocesses.parse().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Invalid number for Python subprocesses ({python_subprocesses}): {err}"
                        ),
                    )
                })?;
                std::num::NonZeroUsize::new(num).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Number of Python subprocesses must be non-zero".to_owned(),
                    )
                })?
            }
            None => std::num::NonZeroUsize::new(2).unwrap(),
        };
        let sqlite_wal = match self.take(ConfigOption::EnableSQLiteWriteAheadLogging) {
            Some(enable) => {
                let enable = enable.to_lowercase();
                match enable.as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid value '{enable}' for enable SQLite WAL mode option, must be true|false")
                    )),
                }
            }
            None => Ok(true),
        }?;

        // Parse the HTTP-RPC listening address and port.
        let http_rpc_addr = http_rpc_addr.parse::<SocketAddr>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid HTTP-RPC listening interface and port ({http_rpc_addr}): {err}"),
            )
        })?;

        let poll_pending = match self.take(ConfigOption::PollPending) {
            Some(enable) => {
                let enable = enable.to_lowercase();
                match enable.as_str() {
                    "true" => Ok(true),
                    "false" => Ok(false),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!(
                            "Invalid value '{enable}' for enable poll pending option, must be true|false"
                        ),
                    )),
                }
            }
            None => Ok(false),
        }?;

        Ok(Configuration {
            ethereum: EthereumConfig {
                url: eth_url,
                password: eth_password,
            },
            http_rpc_addr,
            data_directory,
            python_subprocesses,
            sqlite_wal,
            poll_pending,
            monitoring_addr,
            network,
            custom_gateway,
        })
    }

    /// Returns the [ConfigOption] if present, else returns an [io::Error](std::io::Error).
    fn take_required(&mut self, option: ConfigOption) -> std::io::Result<String> {
        self.take(option).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{option} is a required parameter"),
            )
        })
    }

    /// Returns the [ConfigOption], leaving it set to [None].
    pub fn take(&mut self, option: ConfigOption) -> Option<String> {
        self.0.remove(&option)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_take() {
        let value = Some("Value".to_owned());
        let mut builder = ConfigBuilder::default();
        for option in enum_iterator::all::<ConfigOption>() {
            builder = builder.with(option, value.clone());
            assert_eq!(builder.take(option), value);
            assert_eq!(builder.take(option), None);
        }
    }

    #[test]
    fn default_is_none() {
        // Quite a few tests rely on the default value being None, so we enforce this with a test.
        let mut builder = ConfigBuilder::default();
        for option in enum_iterator::all::<ConfigOption>() {
            assert_eq!(builder.take(option), None);
        }
    }

    mod try_build {
        /// List of [ConfigOption]'s that must be set for [ConfigBuilder] to produce a [Configuration].
        const REQUIRED: &[ConfigOption] = &[ConfigOption::EthereumHttpUrl];

        use super::*;

        /// Some options expect a specific type of value.
        fn get_valid_value(option: ConfigOption) -> String {
            match option {
                ConfigOption::EthereumHttpUrl => "http://localhost",
                ConfigOption::EnableSQLiteWriteAheadLogging => "true",
                _ => "value",
            }
            .to_owned()
        }

        /// Creates a builder with only the required fields set to some valid value.
        fn builder_with_all_required() -> ConfigBuilder {
            let mut builder = ConfigBuilder::default();
            for option in REQUIRED {
                builder = builder.with(*option, Some(get_valid_value(*option)));
            }
            builder
        }

        #[test]
        fn with_all_required_options() {
            let builder = builder_with_all_required();
            assert!(builder.try_build().is_ok());
        }

        #[test]
        fn with_required_missing_should_error() {
            // Any missing required field should fail to build.
            for option in REQUIRED {
                let mut builder = builder_with_all_required();
                builder.take(*option);
                assert!(builder.try_build().is_err(), "{option} failed");
            }
        }

        mod defaults {
            //! Tests that the correct default values are applied during `try_build`.

            use super::builder_with_all_required;

            #[test]
            fn data_directory() {
                let expected = std::env::current_dir().unwrap();
                let config = builder_with_all_required().try_build().unwrap();
                assert_eq!(config.data_directory, expected);
            }

            #[test]
            fn http_rpc_addr() {
                use crate::config::DEFAULT_HTTP_RPC_ADDR;
                use std::net::SocketAddr;

                let expected = DEFAULT_HTTP_RPC_ADDR.parse::<SocketAddr>().unwrap();

                let config = builder_with_all_required().try_build().unwrap();
                assert_eq!(config.http_rpc_addr, expected);
            }

            #[test]
            fn python_subprocesses() {
                use std::num::NonZeroUsize;

                let expected = NonZeroUsize::new(2).unwrap();
                let config = builder_with_all_required().try_build().unwrap();
                assert_eq!(config.python_subprocesses, expected);
            }

            #[test]
            fn sqlite_wal() {
                let expected = true;
                let config = builder_with_all_required().try_build().unwrap();
                assert_eq!(config.sqlite_wal, expected);
            }
        }
    }
}
