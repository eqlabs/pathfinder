//! Provides [ConfigBuilder] which is a convenient and safe way of collecting
//! configuration parameters from various sources and combining them into one.

use std::collections::HashMap;

use reqwest::Url;

use crate::config::{ConfigOption, Configuration, EthereumConfig};

/// A convenient way of collecting and merging configuration options.
///
/// Once finalised, can be converted to [Configuration] using `try_build`, which
/// will check for [REQUIRED] options.
#[derive(Default, PartialEq, Debug)]
pub struct ConfigBuilder(HashMap<ConfigOption, String>);

impl ConfigBuilder {
    /// Sets the [ConfigOption] to value.
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
    /// [REQUIRED] options are set.
    pub fn try_build(mut self) -> std::io::Result<Configuration> {
        // Required parameters.
        let eth_url = self.take_required(ConfigOption::EthereumUrl)?;

        // Parse the Ethereum URL.
        let eth_url = eth_url.parse::<Url>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Invalid Ethereum URL ({}): {}", eth_url, err.to_string()),
            )
        })?;

        // Optional parameters.
        let eth_user = self.take(ConfigOption::EthereumUser);

        Ok(Configuration {
            ethereum: EthereumConfig {
                url: eth_url,
                user: eth_user,
            },
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
        use crate::config::REQUIRED;

        use super::*;

        /// Some options expect a specific type of value.
        fn get_valid_value(option: ConfigOption) -> String {
            match option {
                ConfigOption::EthereumUrl => "http://localhost",
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
                assert!(builder.try_build().is_err());
            }
        }
    }
}
