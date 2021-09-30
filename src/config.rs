//! Contains the node configuration parsing code.
mod builder;
mod cli;
mod file;
mod value;

use anyhow::Result;
use enum_iterator::IntoEnumIterator;
use reqwest::Url;
use std::{fmt::Display, net::IpAddr, path::PathBuf, str::FromStr};

/// Possible configuration options.
#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq, IntoEnumIterator)]
pub enum ConfigOption {
    /// The Ethereum URL.
    EthereumUrl,
    /// The Ethereum user.
    EthereumUser,
    /// The Ethereum password.
    EthereumPassword,
    /// Enable HTTP-RPC server.
    HttpRpcEnable,
    /// The HTTP-RPC server listening interface.
    HttpRpcAddress,
    /// The HTTP-RPC server listening port.
    HttpRpcPort,
}

impl Display for ConfigOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigOption::EthereumUrl => f.write_str("Ethereum URL"),
            ConfigOption::EthereumUser => f.write_str("Ethereum user"),
            ConfigOption::EthereumPassword => f.write_str("Ethereum password"),
            ConfigOption::HttpRpcEnable => f.write_str("Enable HTTP-RPC"),
            ConfigOption::HttpRpcAddress => f.write_str("HTTP-RPC interface"),
            ConfigOption::HttpRpcPort => f.write_str("HTTP-RPC port"),
        }
    }
}

/// Ethereum configuration parameters.
#[derive(Debug, PartialEq)]
pub struct EthereumConfig {
    /// The Ethereum URL.
    pub url: Url,
    /// The optional Ethereum user.
    pub user: Option<String>,
    /// The optional Ethereum password.
    pub password: Option<String>,
}

/// HTTP-RPC server parameters.
#[derive(Debug, PartialEq)]
pub struct HttpRpcConfig {
    /// Enable HTTP-RPC server.
    pub enable: bool,
    /// The HTTP-RPC server listening interface.
    pub address: Option<IpAddr>,
    /// The HTTP-RPC server listening port.
    pub port: Option<u16>,
}

/// Node configuration options.
#[derive(Debug, PartialEq)]
pub struct Configuration {
    /// The Ethereum settings.
    pub ethereum: EthereumConfig,
    /// The HTTP-RPC server settings.
    pub http_rpc: HttpRpcConfig,
}

impl Configuration {
    /// Creates a [node configuration](Configuration) based on the options specified
    /// via the command-line and config file.
    ///
    /// The config filepath may be specified as a command-line parameter, otherwise
    /// it defaults to `$HOME/.starknet/config.toml`.
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
    pub fn parse_cmd_line_and_cfg_file() -> Result<Self> {
        // Parse command-line arguments. This must be first in order to use
        // users config filepath (if supplied).
        let (cfg_filepath, cli_cfg) = cli::parse_cmd_line();

        // Parse configuration file - user specified path, or default path.
        // Default path is allowed to not exist.
        let file_cfg = match cfg_filepath {
            Some(filepath) => {
                let filepath = PathBuf::from_str(&filepath)?;
                Some(file::config_from_filepath(&filepath)?)
            }
            None => match file::config_from_default_filepath() {
                Ok(config) => Some(config),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            },
        };

        let cfg = match file_cfg {
            Some(cfg) => cli_cfg.merge(cfg),
            None => cli_cfg,
        };

        cfg.try_build()
    }
}
