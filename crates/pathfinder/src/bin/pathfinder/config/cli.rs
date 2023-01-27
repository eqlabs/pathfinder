//! Command-line argument parsing
use clap::Arg;
use std::ffi::OsString;

use crate::config::builder::ConfigBuilder;

use super::ConfigOption;

const DATA_DIR_KEY: &str = "data-directory";
const ETH_URL_KEY: &str = "ethereum.url";
const ETH_PASS_KEY: &str = "ethereum.password";
const HTTP_RPC_ADDR_KEY: &str = "http-rpc";
const PYTHON_SUBPROCESSES_KEY: &str = "python-subprocesses";
const SQLITE_WAL: &str = "sqlite-wal";
const POLL_PENDING: &str = "poll-pending";
const MONITOR_ADDRESS: &str = "monitor-address";
const NETWORK: &str = "network";
const GATEWAY: &str = "gateway-url";
const FEEDER_GATEWAY: &str = "feeder-gateway-url";
const CHAIN_ID: &str = "chain-id";

/// Parses the cmd line arguments and returns the specified configuration options.
///
/// Note: This will terminate the program if invalid arguments are supplied.
///       This is intended, as [clap] will show the program usage / help.
pub fn parse_cmd_line() -> ConfigBuilder {
    // A thin wrapper around `parse_args()`. This should be kept thin
    // to enable test coverage without requiring cmd line arg input.
    match parse_args(std::env::args_os()) {
        Ok(cfg) => cfg,
        Err(err) => err.exit(),
    }
}

/// A wrapper around [clap::Command]'s `get_matches_from_safe()` which returns
/// a [ConfigOption].
fn parse_args<I, T>(args: I) -> clap::Result<ConfigBuilder>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = clap_app().try_get_matches_from(args)?;

    let data_directory = args.value_of(DATA_DIR_KEY).map(|s| s.to_owned());
    let ethereum_url = args.value_of(ETH_URL_KEY).map(|s| s.to_owned());
    let ethereum_password = args.value_of(ETH_PASS_KEY).map(|s| s.to_owned());
    let http_rpc_addr = args.value_of(HTTP_RPC_ADDR_KEY).map(|s| s.to_owned());
    let python_subprocesses = args.value_of(PYTHON_SUBPROCESSES_KEY).map(|s| s.to_owned());
    let sqlite_wal = args.value_of(SQLITE_WAL).map(|s| s.to_owned());
    let poll_pending = args.value_of(POLL_PENDING).map(|s| s.to_owned());
    let monitor_address = args.value_of(MONITOR_ADDRESS).map(|s| s.to_owned());
    let network = args.value_of(NETWORK).map(|s| s.to_owned());
    let gateway = args.value_of(GATEWAY).map(|s| s.to_owned());
    let feeder_gateway = args.value_of(FEEDER_GATEWAY).map(|s| s.to_owned());
    let chain_id = args.value_of(CHAIN_ID).map(|s| s.to_owned());

    let cfg = ConfigBuilder::default()
        .with(ConfigOption::EthereumHttpUrl, ethereum_url)
        .with(ConfigOption::EthereumPassword, ethereum_password)
        .with(ConfigOption::HttpRpcAddress, http_rpc_addr)
        .with(ConfigOption::DataDirectory, data_directory)
        .with(ConfigOption::PythonSubprocesses, python_subprocesses)
        .with(ConfigOption::EnableSQLiteWriteAheadLogging, sqlite_wal)
        .with(ConfigOption::PollPending, poll_pending)
        .with(ConfigOption::MonitorAddress, monitor_address)
        .with(ConfigOption::Network, network)
        .with(ConfigOption::GatewayUrl, gateway)
        .with(ConfigOption::FeederGatewayUrl, feeder_gateway)
        .with(ConfigOption::ChainId, chain_id);

    Ok(cfg)
}

/// Defines our command-line interface using [clap::Command].
///
/// Sets the argument names, help strings etc.
fn clap_app() -> clap::Command<'static> {
    use super::DEFAULT_HTTP_RPC_ADDR;
    lazy_static::lazy_static! {
        static ref HTTP_RPC_HELP: String =
            format!("HTTP-RPC listening address [default: {DEFAULT_HTTP_RPC_ADDR}]");
    }

    let version = pathfinder_common::consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT;
    clap::Command::new("Pathfinder")
        .version(version)
        .about("A StarkNet node implemented by Equilibrium. Submit bug reports and issues at https://github.com/eqlabs/pathfinder.")
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
                .value_name("PATH")
                .env("PATHFINDER_DATA_DIRECTORY")
        )
        .arg(
            Arg::new(PYTHON_SUBPROCESSES_KEY)
                .long(PYTHON_SUBPROCESSES_KEY)
                .help("Number of Python subprocesses to start")
                .takes_value(true)
                .value_name("NUM")
                .env("PATHFINDER_PYTHON_SUBPROCESSES")
        )
        .arg(
            Arg::new(SQLITE_WAL)
                .long(SQLITE_WAL)
                .help("Enable SQLite write-ahead logging")
                .takes_value(true)
                .value_name("TRUE/FALSE")
                .env("PATHFINDER_SQLITE_WAL")
        )
        .arg(
            Arg::new(POLL_PENDING)
                .long(POLL_PENDING)
                .help("Enable polling pending block")
                .takes_value(true)
                .value_name("TRUE/FALSE")
                .env("PATHFINDER_POLL_PENDING")
        )
        .arg(
            Arg::new(MONITOR_ADDRESS)
                .long(MONITOR_ADDRESS)
                .help("Pathfinder monitoring address")
                .long_help("The address at which pathfinder will serve monitoring related information.")
                .takes_value(true)
                .value_name("IP:PORT")
                .env("PATHFINDER_MONITOR_ADDRESS")
        )
        .arg(
            Arg::new(NETWORK)
            .long(NETWORK)
            .help("Specify the StarkNet network")
            .long_help(
                r"Specify the StarkNet network for pathfinder to operate on.
Note that 'custom' requires also setting the --gateway-url and --feeder-gateway-url options."
            )
            .value_parser(["mainnet", "testnet", "testnet2", "integration", "custom"])
            .takes_value(true)
            .env("PATHFINDER_NETWORK")
        )
        .arg(
            Arg::new(GATEWAY)
            .long(GATEWAY)
            .help("Set a custom StarkNet gateway url")
            .long_help(
                r"Specify a custom StarkNet gateway url.
                Can be used to run pathfinder on a custom StarkNet network, or to
                use a gateway proxy. Requires '--network custom'."
            )
            .takes_value(true)
            .env("PATHFINDER_GATEWAY_URL")
        )
        .arg(
            Arg::new(FEEDER_GATEWAY)
            .long(FEEDER_GATEWAY)
            .help("Set a custom StarkNet gateway url")
            .long_help(
                r"Specify a custom StarkNet feeder gateway url.
                Can be used to run pathfinder on a custom StarkNet network, or to
                use a gateway proxy. Requires '--network custom'."
            )
            .takes_value(true)
            .env("PATHFINDER_FEEDER_GATEWAY_URL")
        )
        .arg(
            Arg::new(CHAIN_ID)
            .long(CHAIN_ID)
            .help("Set a custom StarkNet chain ID (e.g. SN_GOERLI)")
            .takes_value(true)
            .env("PATHFINDER_CHAIN_ID")
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
        env::remove_var("PATHFINDER_ETHEREUM_API_PASSWORD");
        env::remove_var("PATHFINDER_ETHEREUM_API_URL");
        env::remove_var("PATHFINDER_HTTP_RPC_ADDRESS");
        env::remove_var("PATHFINDER_DATA_DIRECTORY");
        env::remove_var("PATHFINDER_PYTHON_SUBPROCESSES");
        env::remove_var("PATHFINDER_SQLITE_WAL");
        env::remove_var("PATHFINDER_POLL_PENDING");
        env::remove_var("PATHFINDER_MONITOR_ADDRESS");
        env::remove_var("PATHFINDER_NETWORK");
        env::remove_var("PATHFINDER_GATEWAY_URL");
        env::remove_var("PATHFINDER_FEEDER_GATEWAY_URL");
        env::remove_var("PATHFINDER_CHAIN_ID");
    }

    #[test]
    fn ethereum_url_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--ethereum.url", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(value));
    }

    #[test]
    fn ethereum_url_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_ETHEREUM_API_URL", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(value));
    }

    #[test]
    fn ethereum_password_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--ethereum.password", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(value));
    }

    #[test]
    fn ethereum_password_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_ETHEREUM_API_PASSWORD", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(value));
    }

    #[test]
    fn http_rpc_address_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--http-rpc", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::HttpRpcAddress), Some(value));
    }

    #[test]
    fn http_rpc_address_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_HTTP_RPC_ADDRESS", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::HttpRpcAddress), Some(value));
    }

    #[test]
    fn data_directory_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--data-directory", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::DataDirectory), Some(value));
    }

    #[test]
    fn data_directory_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_DATA_DIRECTORY", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::DataDirectory), Some(value));
    }

    #[test]
    fn python_subprocesses_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--python-subprocesses", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::PythonSubprocesses), Some(value));
    }

    #[test]
    fn python_subprocesses_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_PYTHON_SUBPROCESSES", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::PythonSubprocesses), Some(value));
    }

    #[test]
    fn sqlite_wal_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--sqlite-wal", &value]).unwrap();
        assert_eq!(
            cfg.take(ConfigOption::EnableSQLiteWriteAheadLogging),
            Some(value)
        );
    }

    #[test]
    fn sqlite_wal_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_SQLITE_WAL", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(
            cfg.take(ConfigOption::EnableSQLiteWriteAheadLogging),
            Some(value)
        );
    }

    #[test]
    fn poll_pending_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--poll-pending", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::PollPending), Some(value));
    }

    #[test]
    fn poll_pending_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_POLL_PENDING", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::PollPending), Some(value));
    }

    #[test]
    fn monitor_address_long() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--monitor-address", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::MonitorAddress), Some(value));
    }

    #[test]
    fn monitor_address_environment_variable() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        env::set_var("PATHFINDER_MONITOR_ADDRESS", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::MonitorAddress), Some(value));
    }

    #[test]
    fn network() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "mainnet".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--network", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::Network), Some(value));

        let value = "mainnet".to_owned();
        env::set_var("PATHFINDER_NETWORK", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::Network), Some(value));
    }

    #[test]
    fn gateway() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--gateway-url", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::GatewayUrl), Some(value));

        let value = "value".to_owned();
        env::set_var("PATHFINDER_GATEWAY_URL", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::GatewayUrl), Some(value));
    }

    #[test]
    fn feeder_gateway() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--feeder-gateway-url", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::FeederGatewayUrl), Some(value));

        let value = "value".to_owned();
        env::set_var("PATHFINDER_FEEDER_GATEWAY_URL", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::FeederGatewayUrl), Some(value));
    }

    #[test]
    fn chain_id() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let value = "value".to_owned();
        let mut cfg = parse_args(vec!["bin name", "--chain-id", &value]).unwrap();
        assert_eq!(cfg.take(ConfigOption::ChainId), Some(value));

        let value = "value".to_owned();
        env::set_var("PATHFINDER_CHAIN_ID", &value);
        let mut cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg.take(ConfigOption::ChainId), Some(value));
    }

    #[test]
    fn empty_config() {
        let _env_guard = ENV_VAR_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        clear_environment();

        let cfg = parse_args(vec!["bin name"]).unwrap();
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
