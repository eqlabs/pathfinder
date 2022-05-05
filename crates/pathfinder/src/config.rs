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
    /// The User Agent header value to use for the Ethereum URL.
    ///
    /// Deprecated, we now set a version specific user-agent.
    EthereumUserAgent,
    /// The Ethereum password.
    EthereumPassword,
    /// The HTTP-RPC listening socket address.
    HttpRpcAddress,
    /// Path to the node's data directory.
    DataDirectory,
}

impl Display for ConfigOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigOption::EthereumHttpUrl => f.write_str("Ethereum HTTP URL"),
            ConfigOption::EthereumUserAgent => f.write_str("Ethereum user agent"),
            ConfigOption::EthereumPassword => f.write_str("Ethereum password"),
            ConfigOption::DataDirectory => f.write_str("Data directory"),
            ConfigOption::HttpRpcAddress => f.write_str("HTTP-RPC socket address"),
        }
    }
}

/// Ethereum configuration parameters.
#[derive(Debug, PartialEq)]
pub struct EthereumConfig {
    /// The Ethereum URL.
    pub url: Url,
    /// The optional HTTP User-Agent header value to use for Ethereum.
    pub user_agent: Option<String>,
    /// The optional Ethereum password.
    pub password: Option<String>,
}

/// Node configuration options.
#[derive(Debug, PartialEq)]
pub struct Configuration {
    /// The Ethereum settings.
    pub ethereum: EthereumConfig,
    /// The HTTP-RPC listening address and port.
    pub http_rpc_addr: SocketAddr,
    /// The node's data directory.
    pub data_directory: PathBuf,
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

        if cfg.ethereum.user_agent.is_some() {
            tracing::warn!(
                "Ethereum user-agent was provided in the configuration but this option is deprecated. It will be no longer accepted in future releases"
            );
        }

        Ok(cfg)
    }
}
