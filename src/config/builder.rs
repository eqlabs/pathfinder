//! Provides [ConfigBuilder] which is a convenient and safe way of collecting
//! configuration parameters from various sources and combining them into one.

use crate::config::{value::Value, ConfigOption, Configuration, EthereumConfig, HttpRpcConfig};
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
};

/// A convenient way of collecting and merging configuration options.
///
/// Once finalised, can be converted to [Configuration] using `try_build`.
#[derive(Default, PartialEq, Debug)]
pub struct ConfigBuilder(HashMap<ConfigOption, Value>);

impl ConfigBuilder {
    pub fn with<T>(mut self, option: ConfigOption, value: Option<T>) -> Self
    where
        Value: From<T>,
    {
        match value {
            Some(v) => self.0.insert(option, v.into()),
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
    pub fn try_build(mut self) -> Result<Configuration> {
        // Required parameters.
        let eth_url = self
            .take_into(ConfigOption::EthereumUrl)
            .with_context(|| "Invalid Ethereum API URL")?;

        // Optional parameters.
        let eth_user = self.take_into_optional(ConfigOption::EthereumUser)?;
        let eth_password = self.take_into_optional(ConfigOption::EthereumPassword)?;

        // HTTP-RPC server enable flag
        let http_enable = self
            .take_into_optional(ConfigOption::HttpRpcEnable)?
            .unwrap_or_default();
        let http_address = if http_enable {
            #[allow(clippy::unnecessary_lazy_evaluations)]
            self.take_into_optional::<IpAddr>(ConfigOption::HttpRpcAddress)
                .with_context(|| "Invalid HTTP-RPC listening interface")?
                .or_else(|| Some(Ipv4Addr::new(127, 0, 0, 1).into()))
        } else {
            None
        };
        let http_port = if http_enable {
            #[allow(clippy::unnecessary_lazy_evaluations)]
            self.take_into_optional(ConfigOption::HttpRpcPort)
                .with_context(|| "Invalid HTTP-RPC listening port")?
                .or_else(|| Some(9545))
        } else {
            None
        };

        Ok(Configuration {
            ethereum: EthereumConfig {
                url: eth_url,
                user: eth_user,
                password: eth_password,
            },
            http_rpc: HttpRpcConfig {
                enable: http_enable,
                address: http_address,
                port: http_port,
            },
        })
    }

    /// Returns the [ConfigOption] if present, else returns an [`anyhow::Error`].
    fn take_into<T>(&mut self, option: ConfigOption) -> Result<T>
    where
        Value: TryInto<T>,
        <Value as TryInto<T>>::Error: 'static + Send + Sync + Display,
    {
        match self.take_into_optional(option) {
            Ok(Some(t)) => Ok(t),
            Ok(None) => Err(anyhow::anyhow!("{} is a required parameter", option)),
            Err(e) => Err(e),
        }
    }

    /// Returns the [ConfigOption], leaving it set to [None].
    pub fn take_into_optional<T>(&mut self, option: ConfigOption) -> Result<Option<T>>
    where
        Value: TryInto<T>,
        <Value as TryInto<T>>::Error: 'static + Send + Sync + Display,
    {
        match self.0.remove(&option) {
            Some(value) => Ok(Some(
                value
                    .try_into()
                    .map_err(|e| anyhow::anyhow!(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use enum_iterator::IntoEnumIterator;
    use reqwest::Url;

    fn expect_take_into_optional<T>(
        b: &mut ConfigBuilder,
        input: ConfigOption,
        expected: &Option<T>,
        line: u32,
    ) where
        T: std::fmt::Debug + PartialEq,
        Value: TryInto<T>,
        <Value as TryInto<T>>::Error: 'static + Send + Sync + Display,
    {
        let msg = format!(
            "Internal conversion from config::value::Value should succeed at line: {}",
            line
        );

        if expected.is_some() {
            assert_eq!(
                b.take_into_optional(input).expect(&msg),
                *expected,
                "see line: {}",
                line
            );
        }

        assert_eq!(
            b.take_into_optional::<T>(input).expect(&msg),
            None,
            "see line: {}",
            line
        );
    }

    macro_rules! assert_take_into_optional_returns {
        ( $builder:expr, $input:expr, $expected:expr ) => {
            expect_take_into_optional(&mut $builder, $input, $expected, line!());
        };
    }

    macro_rules! assert_take_into_optional_returns_none {
        ( $builder:expr, $input:expr ) => {
            expect_take_into_optional(&mut $builder, $input, &None::<String>, line!());
        };
    }

    #[test]
    fn with_take_into_optional() {
        let mut b = ConfigBuilder::default();
        let strval = Some("Value".to_owned());
        let urlval = Some(Url::from_str("https://any.com").expect("Valid URL"));
        let ipval = Some(IpAddr::from_str("127.0.0.1").expect("Valid IP"));
        let bval = Some(true);
        let u16val = Some(1234);
        b = b.with(ConfigOption::EthereumPassword, strval.clone());
        b = b.with(ConfigOption::EthereumUrl, urlval.clone());
        b = b.with(ConfigOption::EthereumUser, strval.clone());
        b = b.with(ConfigOption::HttpRpcAddress, ipval);
        b = b.with(ConfigOption::HttpRpcEnable, bval);
        b = b.with(ConfigOption::HttpRpcPort, u16val);
        assert_take_into_optional_returns!(b, ConfigOption::EthereumPassword, &strval);
        assert_take_into_optional_returns!(b, ConfigOption::EthereumUrl, &urlval);
        assert_take_into_optional_returns!(b, ConfigOption::EthereumUser, &strval);
        assert_take_into_optional_returns!(b, ConfigOption::HttpRpcAddress, &ipval);
        assert_take_into_optional_returns!(b, ConfigOption::HttpRpcEnable, &bval);
        assert_take_into_optional_returns!(b, ConfigOption::HttpRpcPort, &u16val);
    }

    #[test]
    fn default_is_none() {
        // Quite a few tests rely on the default value being None, so we enforce this with a test.
        let mut builder = ConfigBuilder::default();
        for option in ConfigOption::into_enum_iter() {
            assert_take_into_optional_returns_none!(builder, option)
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
        fn some_builder(
            string: &str,
            url: &str,
            ip: &str,
            boolean: bool,
            uint16: u16,
        ) -> (ConfigBuilder, HashMap<ConfigOption, Value>) {
            let mut builder = ConfigBuilder::default();
            let mut values = HashMap::new();

            let strval = Some(string.to_owned());
            let urlval = Some(Url::from_str(url).expect("Valid URL"));
            let ipval = Some(IpAddr::from_str(ip).expect("Valid IP"));
            let bval = Some(boolean);
            let u16val = Some(uint16);
            builder = builder.with(ConfigOption::EthereumPassword, strval.clone());
            values.insert(ConfigOption::EthereumPassword, strval.clone().into());
            builder = builder.with(ConfigOption::EthereumUrl, urlval.clone());
            values.insert(ConfigOption::EthereumUrl, urlval.into());
            builder = builder.with(ConfigOption::EthereumUser, strval.clone());
            values.insert(ConfigOption::EthereumUser, strval.into());
            builder = builder.with(ConfigOption::HttpRpcAddress, ipval);
            values.insert(ConfigOption::HttpRpcAddress, ipval.into());
            builder = builder.with(ConfigOption::HttpRpcEnable, bval);
            values.insert(ConfigOption::HttpRpcEnable, bval.into());
            builder = builder.with(ConfigOption::HttpRpcPort, u16val);
            values.insert(ConfigOption::HttpRpcPort, u16val.into());

            (builder, values)
        }

        fn some_builder_a() -> (ConfigBuilder, HashMap<ConfigOption, Value>) {
            some_builder("A", "https://a.com", "1.2.3.4", true, 1234)
        }

        fn some_builder_b() -> (ConfigBuilder, HashMap<ConfigOption, Value>) {
            some_builder("B", "https://b.com", "5.6.7.8", false, 1234)
        }

        #[test]
        fn some_some() {
            let (some_1, mut values_1) = some_builder_a();
            let (some_2, _) = some_builder_b();

            let mut merged = some_1.merge(some_2);

            for option in ConfigOption::into_enum_iter() {
                assert_eq!(
                    merged.take_into_optional(option).expect("Take works"),
                    values_1.remove(&option).unwrap().into()
                );
            }
        }

        #[test]
        fn some_none() {
            let (some, mut values) = some_builder_a();
            let none = ConfigBuilder::default();

            let mut merged = some.merge(none);

            for option in ConfigOption::into_enum_iter() {
                assert_eq!(
                    merged.take_into_optional(option).expect("Take works"),
                    values.remove(&option).unwrap().into()
                );
            }
        }

        #[test]
        fn none_some() {
            let (some, mut values) = some_builder_a();
            let none = ConfigBuilder::default();

            let mut merged = none.merge(some);

            for option in ConfigOption::into_enum_iter() {
                assert_eq!(
                    merged.take_into_optional(option).expect("Take works"),
                    values.remove(&option).unwrap().into()
                );
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
        use super::*;

        /// Creates a builder with only the required fields set to some valid value.
        fn builder_with_all_required() -> ConfigBuilder {
            ConfigBuilder::default().with(
                ConfigOption::EthereumUrl,
                Some(Url::from_str("http://localhost").expect("Valid URL")),
            )
        }

        #[test]
        fn with_all_required_options() {
            let builder = builder_with_all_required();
            builder
                .try_build()
                .expect("Succeeds with all required options");
        }

        #[test]
        fn with_required_missing_should_error() {
            // Any missing required field should fail to build.
            let mut builder = builder_with_all_required();
            builder
                .take_into::<Url>(ConfigOption::EthereumUrl)
                .expect("Take works");
            builder.try_build().expect_err("Build fails");
        }
    }
}
