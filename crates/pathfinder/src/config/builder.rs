//! Provides [ConfigBuilder] which is a convenient and safe way of collecting
//! configuration parameters from various sources and combining them into one.

use crate::config::{ConfigOption, Configuration, EthereumConfig};
use reqwest::Url;
use std::{collections::HashMap, net::SocketAddr, path::PathBuf, str::FromStr};

/// A convenient way of collecting and merging configuration options.
///
/// Once finalised, can be converted to [Configuration] using `try_build`.
#[derive(Default, PartialEq, Debug)]
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

    /// Merges two [ConfigBuilder] options together, preferring the values
    /// from [self] if they're not [None].
    pub fn merge(mut self, other: Self) -> Self {
        // `extend` has the opposite effect that we want, so we swop
        // self and other's maps.
        let mut merged = other.0;
        merged.extend(self.0.into_iter());
        self.0 = merged;
        self
    }

    /// Attempts to generate a [Configuration] from the options. Performs type checking
    /// and parsing as required by [Configuration] types. Also ensures that all
    /// required options are set.
    pub fn try_build(mut self) -> std::io::Result<Configuration> {
        use super::DEFAULT_HTTP_RPC_ADDR;

        // Required parameters.
        let eth_url = self.take_required(ConfigOption::EthereumHttpUrl)?;

        // Parse the Ethereum URL.
        let eth_url = eth_url.parse::<Url>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid Ethereum URL ({}): {}", eth_url, err),
            )
        })?;

        // Optional parameters.
        let eth_password = self.take(ConfigOption::EthereumPassword);
        let sequencer_url = match self.take(ConfigOption::SequencerHttpUrl) {
            Some(url) => {
                let url = url.parse::<Url>().map_err(|err| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid Sequencer URL ({}): {}", url, err),
                    )
                })?;

                Some(url)
            }
            None => None,
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
                            "Invalid number for Python subprocesses ({}): {}",
                            python_subprocesses, err
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

        // Parse the HTTP-RPC listening address and port.
        let http_rpc_addr = http_rpc_addr.parse::<SocketAddr>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid HTTP-RPC listening interface and port ({}): {}",
                    http_rpc_addr, err
                ),
            )
        })?;

        Ok(Configuration {
            ethereum: EthereumConfig {
                url: eth_url,
                password: eth_password,
            },
            http_rpc_addr,
            data_directory,
            sequencer_url,
            python_subprocesses,
        })
    }

    /// Returns the [ConfigOption] if present, else returns an [io::Error](std::io::Error).
    fn take_required(&mut self, option: ConfigOption) -> std::io::Result<String> {
        self.take(option).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("{} is a required parameter", option),
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
    use enum_iterator::IntoEnumIterator;

    use super::*;

    #[test]
    fn with_take() {
        let value = Some("Value".to_owned());
        let mut builder = ConfigBuilder::default();
        for option in ConfigOption::into_enum_iter() {
            builder = builder.with(option, value.clone());
            assert_eq!(builder.take(option), value);
            assert_eq!(builder.take(option), None);
        }
    }

    #[test]
    fn default_is_none() {
        // Quite a few tests rely on the default value being None, so we enforce this with a test.
        let mut builder = ConfigBuilder::default();
        for option in ConfigOption::into_enum_iter() {
            assert_eq!(builder.take(option), None);
        }
    }

    mod merge {
        //! Tests the [ConfigBuilder] merge order permutations, to ensure that
        //! all fields follow the convention that `x.merge(y)` should prefer
        //! `x` unless it is [`None`].
        use std::collections::HashMap;

        use super::*;

        /// Generates a [ConfigBuilder] with all fields set. Values for each field
        /// are unique and prefixed with `prefix`. Also returns the values set.
        fn some_builder_with_prefix(
            prefix: &str,
        ) -> (ConfigBuilder, HashMap<ConfigOption, Option<String>>) {
            let mut builder = ConfigBuilder::default();
            let mut values = HashMap::new();

            for (idx, option) in ConfigOption::into_enum_iter().enumerate() {
                let value = Some(format!("{} {}", prefix, idx));

                builder = builder.with(option, value.clone());
                values.insert(option, value);
            }

            (builder, values)
        }

        #[test]
        fn some_some() {
            let (some_1, mut values_1) = some_builder_with_prefix("a");
            let (some_2, _) = some_builder_with_prefix("b");

            let mut merged = some_1.merge(some_2);

            for option in ConfigOption::into_enum_iter() {
                assert_eq!(merged.take(option), values_1.remove(&option).unwrap());
            }
        }

        #[test]
        fn some_none() {
            let (some, mut values) = some_builder_with_prefix("a");
            let none = ConfigBuilder::default();

            let mut merged = some.merge(none);

            for option in ConfigOption::into_enum_iter() {
                assert_eq!(merged.take(option), values.remove(&option).unwrap());
            }
        }

        #[test]
        fn none_some() {
            let (some, mut values) = some_builder_with_prefix("a");
            let none = ConfigBuilder::default();

            let mut merged = none.merge(some);

            for option in ConfigOption::into_enum_iter() {
                assert_eq!(merged.take(option), values.remove(&option).unwrap());
            }
        }

        #[test]
        fn none_none() {
            let none_1 = ConfigBuilder::default();
            let none_2 = ConfigBuilder::default();

            let merged = none_1.merge(none_2);

            assert_eq!(merged, ConfigBuilder::default());
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
        }
    }
}
