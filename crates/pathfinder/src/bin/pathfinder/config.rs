//! Contains the node configuration parsing code.
mod builder;
mod cli;
mod file;

use std::{fmt::Display, net::SocketAddr, path::PathBuf, str::FromStr};

use enum_iterator::IntoEnumIterator;
use reqwest::Url;

const DEFAULT_HTTP_RPC_ADDR: &str = "127.0.0.1:9545";

/// Possible configuration options.
#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq, IntoEnumIterator)]
pub enum ConfigOption {
    /// The Ethereum URL.
    EthereumHttpUrl,
    /// The Ethereum password.
    EthereumPassword,
    /// The HTTP-RPC listening socket address.
    HttpRpcAddress,
    /// Path to the node's data directory.
    DataDirectory,
    /// The Sequencer's HTTP URL.
    SequencerHttpUrl,
    /// Number of Python sub-processes to start.
    PythonSubprocesses,
    /// Enable SQLite write-ahead logging.
    EnableSQLiteWriteAheadLogging,
    /// Enable pending polling.
    PollPending,
    /// Enables and sets the monitoring endpoint
    MonitorAddress,
    /// Chooses Integration network instead of testnet.
    Integration,
    /// Chooses Testnet 2 network.
    Testnet2,
    /// Specify the network.
    Network,
    /// Specify the StarkNet gateway URL.
    GatewayUrl,
    /// Specify the StarkNet feeder gateway URL.
    FeederGatewayUrl,
}

impl Display for ConfigOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigOption::EthereumHttpUrl => f.write_str("Ethereum HTTP URL"),
            ConfigOption::EthereumPassword => f.write_str("Ethereum password"),
            ConfigOption::DataDirectory => f.write_str("Data directory"),
            ConfigOption::HttpRpcAddress => f.write_str("HTTP-RPC socket address"),
            ConfigOption::SequencerHttpUrl => f.write_str("Sequencer HTTP URL"),
            ConfigOption::PythonSubprocesses => f.write_str("Number of Python subprocesses"),
            ConfigOption::EnableSQLiteWriteAheadLogging => {
                f.write_str("Enable SQLite write-ahead logging")
            }
            ConfigOption::PollPending => f.write_str("Enable pending block polling"),
            ConfigOption::MonitorAddress => f.write_str("Pathfinder monitoring address"),
            ConfigOption::Integration => f.write_str("Select integration network"),
            ConfigOption::Testnet2 => f.write_str("Select Testnet 2 network"),
            ConfigOption::Network => f.write_str("Specify the StarkNet network"),
            ConfigOption::GatewayUrl => f.write_str("Specify the StarkNet gateway URL"),
            ConfigOption::FeederGatewayUrl => f.write_str("Specify the StarkNet feeder gateway URL"),
        }
    }
}

/// Ethereum configuration parameters.
#[derive(Debug, PartialEq, Eq)]
pub struct EthereumConfig {
    /// The Ethereum URL.
    pub url: Url,
    /// The optional Ethereum password.
    pub password: Option<String>,
}

/// Node configuration options.
#[derive(Debug, PartialEq, Eq)]
pub struct Configuration {
    /// The Ethereum settings.
    pub ethereum: EthereumConfig,
    /// The HTTP-RPC listening address and port.
    pub http_rpc_addr: SocketAddr,
    /// The node's data directory.
    pub data_directory: PathBuf,
    /// The Sequencer's HTTP URL.
    pub sequencer_url: Option<Url>,
    /// The number of Python subprocesses to start.
    pub python_subprocesses: std::num::NonZeroUsize,
    /// Enable SQLite write-ahead logging.
    pub sqlite_wal: bool,
    /// Enable pending polling.
    pub poll_pending: bool,
    /// The node's monitoring address and port.
    pub monitoring_addr: Option<SocketAddr>,
    /// Select integration network.
    pub integration: bool,
    /// Select testnet 2 network.
    pub testnet2: bool,
    /// The StarkNet network.
    pub network: Option<String>,
    /// Custom StarkNet gateway URLs. TODO: replace with struct.
    pub custom_gateway: Option<(Url, Url)>,
}

impl Configuration {
    /// Creates a [node configuration](Configuration) based on the options specified
    /// via the command-line and config file.
    ///
    /// The config filepath may be specified as a command-line parameter.
    ///
    /// Options from the command-line and config file will be merged, with the
    /// command-line taking precedence. It is valid for no configuration file to exist,
    /// so long as all required options are covered by the command-line arguments.
    ///
    /// Errors if the configuration file couldn't be parsed, or if any required options
    /// are not specified.
    ///
    /// Note: This will terminate the program if invalid command-line arguments are supplied.
    ///       This is intended, as [clap] will show the program usage / help.
    pub fn parse_cmd_line_and_cfg_file() -> std::io::Result<Self> {
        // Parse command-line arguments. This must be first in order to use
        // users config filepath (if supplied).
        let (cfg_filepath, cli_cfg) = cli::parse_cmd_line();

        if cfg_filepath.is_some() {
            tracing::warn!("'--config' is deprecated. Consider using environment variables in .env files to retain the same functionality.");
        }

        // Parse configuration file if specified.
        let file_cfg = match cfg_filepath {
            Some(filepath) => {
                let filepath = PathBuf::from_str(&filepath).map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string())
                })?;
                Some(file::config_from_filepath(&filepath)?)
            }
            None => None,
        };

        let cfg = match file_cfg {
            Some(cfg) => cli_cfg.merge(cfg),
            None => cli_cfg,
        };

        let cfg = cfg.try_build()?;

        if cfg.integration && cfg.testnet2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot use both integration and testnet 2 at the same time. Please choose one."
                    .to_string(),
            ));
        }

        if cfg.custom_gateway.is_some() && cfg.sequencer_url.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot use both custom gateway and sequencer-url at the same time. Please use gateway only."
                    .to_string(),
            ));
        }

        if cfg.network.is_some() && cfg.integration {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot specify both network and integration options at the same time. Please use network only."
                    .to_string(),
            ));
        }

        if cfg.network.is_some() && cfg.testnet2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Cannot specify both network and testnet2 options at the same time. Please use network only."
                    .to_string(),
            ));
        }

        // Emit warning logs for deprecated configuration options.
        // TODO: remove warnings and the options in next major release.
        if cfg.sequencer_url.is_some() {
            tracing::warn!("'--sequencer-url' is deprecated, please use '--gateway' instead");
        }

        if cfg.integration {
            tracing::warn!(
                "'--integration' is deprecated, please use '--network integration' instead"
            );
        }

        if cfg.testnet2 {
            tracing::warn!("'--testnet2' is deprecated, please use '--network testnet2' instead");
        }

        Ok(cfg)
    }
}
