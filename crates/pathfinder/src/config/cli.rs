//! Command-line argument parsing
use clap::Arg;
use std::ffi::OsString;

use crate::config::builder::ConfigBuilder;

use super::ConfigOption;

const CONFIG_KEY: &str = "config";
const DATA_DIR_KEY: &str = "data-directory";
const ETH_URL_KEY: &str = "ethereum.url";
const ETH_USER_AGENT_KEY: &str = "ethereum.user-agent";
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

/// A wrapper around [clap::Command]'s `get_matches_from_safe()` which returns
/// a [ConfigOption].
fn parse_args<I, T>(args: I) -> clap::Result<(Option<String>, ConfigBuilder)>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = clap_app().try_get_matches_from(args)?;

    let config_filepath = args.value_of(CONFIG_KEY).map(|s| s.to_owned());
    let data_directory = args.value_of(DATA_DIR_KEY).map(|s| s.to_owned());
    let ethereum_url = args.value_of(ETH_URL_KEY).map(|s| s.to_owned());
    let ethereum_user_agent = args.value_of(ETH_USER_AGENT_KEY).map(|s| s.to_owned());
    let ethereum_password = args.value_of(ETH_PASS_KEY).map(|s| s.to_owned());
    let http_rpc_addr = args.value_of(HTTP_RPC_ADDR_KEY).map(|s| s.to_owned());

    let cfg = ConfigBuilder::default()
        .with(ConfigOption::EthereumHttpUrl, ethereum_url)
        .with(ConfigOption::EthereumUserAgent, ethereum_user_agent)
        .with(ConfigOption::EthereumPassword, ethereum_password)
        .with(ConfigOption::HttpRpcAddress, http_rpc_addr)
        .with(ConfigOption::DataDirectory, data_directory);

    Ok((config_filepath, cfg))
}

/// Defines our command-line interface using [clap::Command].
///
/// Sets the argument names, help strings etc.
fn clap_app() -> clap::Command<'static> {
    use super::DEFAULT_HTTP_RPC_ADDR;
    lazy_static::lazy_static! {
        static ref HTTP_RPC_HELP: String =
            format!("HTTP-RPC listening address [default: {}]", DEFAULT_HTTP_RPC_ADDR);
    }

    let version = env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT");
    clap::Command::new("Pathfinder")
        .version(version)
        .about("A StarkNet node implemented by Equilibrium. Submit bug reports and issues at https://github.com/eqlabs/pathfinder.")
        .arg(
            Arg::new(CONFIG_KEY)
                .short('c')
                .long(CONFIG_KEY)
                .help("Path to the configuration file.")
                .value_name("FILE")
                .takes_value(true),
        )
        .arg(
            Arg::new(ETH_USER_AGENT_KEY)
                .long(ETH_USER_AGENT_KEY)
                .help("Ethereum API user")
                .takes_value(true)
                .env("PATHFINDER_ETHEREUM_API_USER_AGENT")
                .long_help("The optional user to use for the Ethereum API"),
        )
        .arg(
            Arg::new(ETH_PASS_KEY)
                .long(ETH_PASS_KEY)
                .help("Ethereum API password")
                .takes_value(true)
                .env("PATHFINDER_ETHEREUM_API_PASSWORD")
                .long_help("The optional password to use for the Ethereum API"),
        )
        .arg(
            Arg::new(ETH_URL_KEY)
                .long(ETH_URL_KEY)
                .help("Ethereum API endpoint")
                .takes_value(true)
                .value_name("HTTP(s) URL")
                .env("PATHFINDER_ETHEREUM_API_URL")
                .long_help(r"This should point to the HTTP RPC endpoint of your Ethereum entry-point, typically a local Ethereum client or a hosted gateway service such as Infura or Cloudflare.
Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   https://localhost:8545"))
        .arg(
            Arg::new(HTTP_RPC_ADDR_KEY)
                .long(HTTP_RPC_ADDR_KEY)
                .help(HTTP_RPC_HELP.as_ref())
                .takes_value(true)
                .value_name("IP:PORT")
                .env("PATHFINDER_HTTP_RPC_ADDRESS")
        )
        .arg(
            Arg::new(DATA_DIR_KEY)
                .long(DATA_DIR_KEY)
                .help("Directory where the node should store its data".as_ref())
                .takes_value(true)
                .value_name("IP:PORT")
                .env("PATHFINDER_DATA_DIRECTORY")
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::sync::Mutex;

    lazy_static::lazy_static! {
        // prevents running tests in parallel, since these depend on
        // process-global environment variables
        static ref ENV_VAR_MUTEX: Mutex<()> = Mutex::new(());
    }

    fn clear_environment() {
        env::remove_var("PATHFINDER_ETHEREUM_API_USER_AGENT");
        env::remove_var("PATHFINDER_ETHEREUM_API_PASSWORD");
        env::remove_var("PATHFINDER_ETHEREUM_API_URL");
        env::remove_var("PATHFINDER_HTTP_RPC_ADDRESS");
        env::remove_var("PATHFINDER_DATA_DIRECTORY");
    }

    #[test]
    fn ethereum_url_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.url", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(value));
    }

    #[test]
    fn ethereum_url_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_ETHEREUM_API_URL", &value);
        let (_, mut cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(value));
    }

    #[test]
    fn ethereum_user_agent_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.user-agent", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUserAgent), Some(value));
    }

    #[test]
    fn ethereum_user_agent_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_ETHEREUM_API_USER_AGENT", &value);
        let (_, mut cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumUserAgent), Some(value));
    }

    #[test]
    fn ethereum_password_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--ethereum.password", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(value));
    }

    #[test]
    fn ethereum_password_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_ETHEREUM_API_PASSWORD", &value);
        let (_, mut cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(value));
    }

    #[test]
    fn config_filepath_short() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (filepath, _) = parse_args(vec!["bin name", "-c", &value]).unwrap();
        assert_eq!(filepath, Some(value));
    }

    #[test]
    fn config_filepath_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (filepath, _) = parse_args(vec!["bin name", "--config", &value]).unwrap();
        assert_eq!(filepath, Some(value));
    }

    #[test]
    fn http_rpc_address_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--http-rpc", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::HttpRpcAddress), Some(value));
    }

    #[test]
    fn http_rpc_address_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_HTTP_RPC_ADDRESS", &value);
        let (_, mut cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::HttpRpcAddress), Some(value));
    }

    #[test]
    fn data_directory_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let (_, mut cfg) = parse_args(vec!["bin name", "--data-directory", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::DataDirectory), Some(value));
    }

    #[test]
    fn data_directory_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_DATA_DIRECTORY", &value);
        let (_, mut cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::DataDirectory), Some(value));
    }

    #[test]
    fn empty_config() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let (filepath, cfg) = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(filepath, None);
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
