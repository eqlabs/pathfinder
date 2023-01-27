//! Contains the node configuration parsing code.
mod builder;
mod cli;

use std::{fmt::Display, net::SocketAddr, path::PathBuf};

use enum_iterator::Sequence;
use reqwest::Url;

const DEFAULT_HTTP_RPC_ADDR: &str = "127.0.0.1:9545";

/// Possible configuration options.
#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq, Sequence)]
pub enum ConfigOption {
    /// The Ethereum URL.
    EthereumHttpUrl,
    /// The Ethereum password.
    EthereumPassword,
    /// The HTTP-RPC listening socket address.
    HttpRpcAddress,
    /// Path to the node's data directory.
    DataDirectory,
    /// Number of Python sub-processes to start.
    PythonSubprocesses,
    /// Enable SQLite write-ahead logging.
    EnableSQLiteWriteAheadLogging,
    /// Enable pending polling.
    PollPending,
    /// Enables and sets the monitoring endpoint
    MonitorAddress,
    /// Specify the network.
    Network,
    /// Specify the StarkNet gateway URL.
    GatewayUrl,
    /// Specify the StarkNet feeder gateway URL.
    FeederGatewayUrl,
    /// Specify the StarkNet chain ID for custom gateways.
    ChainId,
}

impl Display for ConfigOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigOption::EthereumHttpUrl => f.write_str("Ethereum HTTP URL"),
            ConfigOption::EthereumPassword => f.write_str("Ethereum password"),
            ConfigOption::DataDirectory => f.write_str("Data directory"),
            ConfigOption::HttpRpcAddress => f.write_str("HTTP-RPC socket address"),
            ConfigOption::PythonSubprocesses => f.write_str("Number of Python subprocesses"),
            ConfigOption::EnableSQLiteWriteAheadLogging => {
                f.write_str("Enable SQLite write-ahead logging")
            }
            ConfigOption::PollPending => f.write_str("Enable pending block polling"),
            ConfigOption::MonitorAddress => f.write_str("Pathfinder monitoring address"),
            ConfigOption::Network => f.write_str("Specify the StarkNet network"),
            ConfigOption::GatewayUrl => f.write_str("Specify the StarkNet gateway URL"),
            ConfigOption::FeederGatewayUrl => {
                f.write_str("Specify the StarkNet feeder gateway URL")
            }
            ConfigOption::ChainId => f.write_str("Specify the StarkNet chain ID"),
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
    /// The number of Python subprocesses to start.
    pub python_subprocesses: std::num::NonZeroUsize,
    /// Enable SQLite write-ahead logging.
    pub sqlite_wal: bool,
    /// Enable pending polling.
    pub poll_pending: bool,
    /// The node's monitoring address and port.
    pub monitoring_addr: Option<SocketAddr>,
    /// The StarkNet network.
    pub network: Option<String>,
    /// Custom StarkNet gateway URLs.
    ///
    /// Args are: (gateway, feeder gateway, chain ID)
    pub custom_gateway: Option<(Url, Url, String)>,
}

impl Configuration {
    /// Creates a [node configuration](Configuration) based on the options specified
    /// via the command-line.
    ///
    /// Note: This will terminate the program if invalid command-line arguments are supplied.
    ///       This is intended, as [clap] will show the program usage / help.
    pub fn parse_cmd_line() -> anyhow::Result<Self> {
        // Parse command-line arguments. This must be first in order to use
        // users config filepath (if supplied).
        let cfg = cli::parse_cmd_line().try_build()?;

        Ok(cfg)
    }
}
