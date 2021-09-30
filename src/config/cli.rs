//! Command-line argument parsing
use clap::{crate_version, Arg};
use reqwest::Url;
use std::{ffi::OsString, fmt::Display, net::IpAddr};

use crate::config::builder::ConfigBuilder;

use super::ConfigOption;

const CONFIG_KEY: &str = "config";
const ETH_URL_KEY: &str = "ethereum.url";
const ETH_USER_KEY: &str = "ethereum.user";
const ETH_PASS_KEY: &str = "ethereum.password";
const HTTP_RPC_ENABLE_KEY: &str = "http";
const HTTP_RPC_ADDR_KEY: &str = "http.address";
const HTTP_RPC_PORT_KEY: &str = "http.port";

/// Parses the cmd line arguments and returns the optional
/// configuration file's path and the specified configuration options.
///
/// Note: This will terminate the program if invalid arguments are supplied.
///       This is intended, as [clap] will show the program usage / help.
pub fn parse_cmd_line() -> (Option<String>, ConfigBuilder) {
    // A thin wrapper around `parse_args()`. This should be kept thin
    // to enable test coverage without requiring cmd line arg input.
    match parse_args(&mut std::env::args_os()) {
        Ok(cfg) => cfg,
        Err(err) => err.exit(),
    }
}

/// A wrapper around [clap::App]'s `get_matches_from_safe()` which returns
/// a [ConfigOptions].
fn parse_args<I, T>(args: I) -> clap::Result<(Option<String>, ConfigBuilder)>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    fn to_value_validation_error<E>(err: E, context: &str) -> clap::Error
    where
        E: Display,
    {
        clap::Error::with_description(
            format!("{}: {}.", context, err).as_str(),
            clap::ErrorKind::ValueValidation,
        )
    }

    let args = clap_app().get_matches_from_safe(args)?;

    let config_filepath = args.value_of(CONFIG_KEY).map(|s| s.to_owned());
    let ethereum_url = match args.value_of(ETH_URL_KEY) {
        Some(s) => Some(
            s.to_owned()
                .parse::<Url>()
                .map_err(|e| to_value_validation_error(e, "Invalid Ethereum url"))?,
        ),
        None => None,
    };
    let ethereum_user = args.value_of(ETH_USER_KEY).map(|s| s.to_owned());
    let ethereum_password = args.value_of(ETH_PASS_KEY).map(|s| s.to_owned());
    let http_rpc_enable = if args.is_present(HTTP_RPC_ENABLE_KEY) {
        Some(true)
    } else {
        None
    };
    let http_rpc_address =
        match args.value_of(HTTP_RPC_ADDR_KEY) {
            Some(s) => Some(s.to_owned().parse::<IpAddr>().map_err(|e| {
                to_value_validation_error(e, "Invalid HTTP-RPC listener interface")
            })?),
            None => None,
        };
    let http_rpc_port = match args.value_of(HTTP_RPC_PORT_KEY) {
        Some(s) => Some(
            s.parse::<u16>()
                .map_err(|e| to_value_validation_error(e, "Invalid HTTP-RPC listener port"))?,
        ),
        None => None,
    };

    let cfg = ConfigBuilder::default()
        .with(ConfigOption::EthereumUrl, ethereum_url)
        .with(ConfigOption::EthereumUser, ethereum_user)
        .with(ConfigOption::EthereumPassword, ethereum_password)
        .with(ConfigOption::HttpRpcEnable, http_rpc_enable)
        .with(ConfigOption::HttpRpcAddress, http_rpc_address)
        .with(ConfigOption::HttpRpcPort, http_rpc_port);

    Ok((config_filepath, cfg))
}

/// Defines our command-line interface using [clap::App].
///
/// Sets the argument names, help strings etc.
fn clap_app() -> clap::App<'static, 'static> {
    use super::file::DEFAULT_FILEPATH;
    lazy_static::lazy_static! {
        static ref CFG_LONG_HELP: String =
            format!("Path to the toml configuration file. Defaults to {}", DEFAULT_FILEPATH.to_string_lossy());
    }

    clap::App::new("Equilibrium StarkNet Node")
        .version(crate_version!())
        .about("A StarkNet node")
        .arg(
            Arg::with_name(CONFIG_KEY)
                .short("c")
                .long(CONFIG_KEY)
                .help("Path to the configuration file")
                .long_help(&CFG_LONG_HELP)
                .value_name("FILE")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(ETH_USER_KEY)
                .long(ETH_USER_KEY)
                .help("Ethereum API user")
                .takes_value(true)
                .long_help("The optional user to use for the Ethereum API"),
        )
        .arg(
            Arg::with_name(ETH_PASS_KEY)
                .long(ETH_PASS_KEY)
                .help("Ethereum API password")
                .takes_value(true)
                .long_help("The optional password to use for the Ethereum API"),
        )
        .arg(
            Arg::with_name(ETH_URL_KEY)
                .long(ETH_URL_KEY)
                .help("Ethereum API URL")
                .takes_value(true)
                .value_name("URL")
                .long_help(r#"This should point to the RPC endpoint of your Ethereum entry-point, typically a local Ethereum light client or a hosted gateway service such as Infura or Cloudflare.
Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   http://localhost:8545"#),
        ).arg(
            Arg::with_name(HTTP_RPC_ENABLE_KEY)
                .long(HTTP_RPC_ENABLE_KEY)
                .help("Enable the HTTP-RPC server")
        ).arg(
            Arg::with_name(HTTP_RPC_ADDR_KEY)
                .long(HTTP_RPC_ADDR_KEY)
                .help("HTTP-RPC server listening interface")
                .takes_value(true)
                .long_help("Used to specify a custom HTTP-RPC server listening interface"),
        ).arg(
            Arg::with_name(HTTP_RPC_PORT_KEY)
                .long(HTTP_RPC_PORT_KEY)
                .help("HTTP-RPC server listening port")
                .takes_value(true)
                .long_help("Used to specify a custom HTTP-RPC server listening port"),
        )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn ethereum_url_long() {
        let value = "http://localhost";
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.url", value]).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumUrl)
                .expect("Take works fine."),
            Some(Url::from_str(value).expect("Valid URL."))
        );
    }

    #[test]
    fn ethereum_user_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.user", &value]).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumUser)
                .expect("Take works fine."),
            Some(value)
        );
    }

    #[test]
    fn ethereum_password_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.password", &value]).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::EthereumPassword)
                .expect("Take works fine."),
            Some(value)
        );
    }

    #[test]
    fn http_rpc_addr_long() {
        let value = "127.0.0.1";
        let (_, mut cfg) = parse_args(vec!["bin name", "--http.address", &value]).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcAddress)
                .expect("Take works fine."),
            Some(IpAddr::from_str(value).expect("Valid IP."))
        );
    }

    #[test]
    fn http_rpc_enable_long() {
        let (_, mut cfg) = parse_args(vec!["bin name", "--http"]).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcEnable)
                .expect("Take works fine."),
            Some(true)
        );
    }

    #[test]
    fn http_rpc_port_long() {
        let (_, mut cfg) = parse_args(vec!["bin name", "--http.port", "1234"]).unwrap();
        assert_eq!(
            cfg.take_into_optional(ConfigOption::HttpRpcPort)
                .expect("Take works fine."),
            Some(1234_u16)
        );
    }

    #[test]
    fn config_filepath_short() {
        let value = "value".to_owned();
        let (filepath, _) = parse_args(vec!["bin name", "-c", &value]).unwrap();
        assert_eq!(filepath, Some(value));
    }

    #[test]
    fn config_filepath_long() {
        let value = "value".to_owned();
        let (filepath, _) = parse_args(vec!["bin name", "--config", &value]).unwrap();
        assert_eq!(filepath, Some(value));
    }

    #[test]
    fn empty_config() {
        let (filepath, cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(filepath, None);
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
