//! Command-line argument parsing
use clap::Arg;
use std::ffi::OsString;

use crate::config::builder::ConfigBuilder;

use super::ConfigOption;

const CONFIG_KEY: &str = "config";
const ETH_URL_KEY: &str = "ethereum.url";
const ETH_USER_KEY: &str = "ethereum.user";
const ETH_PASS_KEY: &str = "ethereum.password";
const HTTP_RPC_ADDR_KEY: &str = "http-rpc";

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
/// a [ConfigOption].
fn parse_args<I, T>(args: I) -> clap::Result<(Option<String>, ConfigBuilder)>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = clap_app().get_matches_from_safe(args)?;

    let config_filepath = args.value_of(CONFIG_KEY).map(|s| s.to_owned());
    let ethereum_url = args.value_of(ETH_URL_KEY).map(|s| s.to_owned());
    let ethereum_user = args.value_of(ETH_USER_KEY).map(|s| s.to_owned());
    let ethereum_password = args.value_of(ETH_PASS_KEY).map(|s| s.to_owned());
    let http_rpc_addr = args.value_of(HTTP_RPC_ADDR_KEY).map(|s| s.to_owned());

    let cfg = ConfigBuilder::default()
        .with(ConfigOption::EthereumHttpUrl, ethereum_url)
        .with(ConfigOption::EthereumUser, ethereum_user)
        .with(ConfigOption::EthereumPassword, ethereum_password)
        .with(ConfigOption::HttpRpcAddress, http_rpc_addr);

    Ok((config_filepath, cfg))
}

/// Defines our command-line interface using [clap::App].
///
/// Sets the argument names, help strings etc.
fn clap_app() -> clap::App<'static, 'static> {
    use super::DEFAULT_HTTP_RPC_ADDR;
    lazy_static::lazy_static! {
        static ref HTTP_RPC_HELP: String =
            format!("HTTP-RPC listening address [default: {}]", DEFAULT_HTTP_RPC_ADDR);
    }

    let version = env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT");
    clap::App::new("Pathfinder")
        .version(version)
        .about("A StarkNet node implemented by Equilibrium. Submit bug reports and issues at https://github.com/eqlabs/pathfinder.")
        .arg(
            Arg::with_name(CONFIG_KEY)
                .short("c")
                .long(CONFIG_KEY)
                .help("Path to the configuration file.")
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
                .help("Ethereum API endpoint")
                .takes_value(true)
                .value_name("HTTP(s) URL")
                .long_help(r"This should point to the HTTP RPC endpoint of your Ethereum entry-point, typically a local Ethereum client or a hosted gateway service such as Infura or Cloudflare.
Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   https://localhost:8545"))
        .arg(
            Arg::with_name(HTTP_RPC_ADDR_KEY)
                .long(HTTP_RPC_ADDR_KEY)
                .help(&HTTP_RPC_HELP)
                .takes_value(true)
                .value_name("IP:PORT")
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_url_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.url", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(value));
    }

    #[test]
    fn ethereum_user_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.user", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUser), Some(value));
    }

    #[test]
    fn ethereum_password_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.password", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(value));
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
    fn http_rpc_address_long() {
        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--http-rpc", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::HttpRpcAddress), Some(value));
    }

    #[test]
    fn empty_config() {
        let (filepath, cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(filepath, None);
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
