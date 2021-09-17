//! Command-line argument parsing
use clap::{crate_version, Arg};
use std::ffi::OsString;

use crate::config::builder::ConfigBuilder;

use super::ConfigOption;

const ETH_URL_KEY: &str = "ethereum.url";
const ETH_USER_KEY: &str = "ethereum.user";
const CONFIG_KEY: &str = "config";

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
    let args = clap_app().get_matches_from_safe(args)?;

    let config_filepath = args.value_of(CONFIG_KEY).map(|s| s.to_owned());
    let ethereum_url = args.value_of(ETH_URL_KEY).map(|s| s.to_owned());
    let ethereum_user = args.value_of(ETH_USER_KEY).map(|s| s.to_owned());

    let cfg = ConfigBuilder::default()
        .with(ConfigOption::EthereumUrl, ethereum_url)
        .with(ConfigOption::EthereumUser, ethereum_user);

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
                .short("u")
                .long(ETH_USER_KEY)
                .help("Ethereum API user")
                .takes_value(true)
                .value_name("URL")
                .long_help("The optional user to use for the Ethereum API"),
        )
        .arg(
            Arg::with_name(ETH_URL_KEY)
                .short("e")
                .long(ETH_URL_KEY)
                .help("Ethereum API URL")
                .takes_value(true)
                .value_name("URL")
                .long_help(r#"This should point to the RPC endpoint of your Ethereum entry-point, typically a local Ethereum light client or a hosted gateway service such as Infura or Cloudflare.
Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   127.0.0.1:8545"#))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_url_short() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "-e", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUrl), Some(value));
    }

    #[test]
    fn ethereum_url_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.url", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUrl), Some(value));
    }

    #[test]
    fn ethereum_user_short() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "-u", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUser), Some(value));
    }

    #[test]
    fn ethereum_user_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.user", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUser), Some(value));
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
