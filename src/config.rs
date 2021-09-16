//! Contains the node configuration parsing code.
mod cli;
mod file;

use std::{path::PathBuf, str::FromStr};

use crate::config::{cli::CliConfig, file::FileConfig};

/// Node configuration options.
#[derive(Debug, PartialEq)]
pub struct Configuration {
    /// The Ethereum RPC endpoint.
    pub ethereum_rpc_url: String,
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
    pub fn parse_cmd_line_and_cfg_file() -> std::io::Result<Self> {
        // Parse command-line arguments. This must be first in order to use
        // users config filepath (if supplied).
        let cli_cfg = cli::CliConfig::parse_cmd_line();

        // Parse configuration file - user specified path, or default path.
        // Default path is allowed to not exist.
        let file_cfg = match &cli_cfg.config_filepath {
            Some(filepath) => {
                let filepath = PathBuf::from_str(filepath).map_err(|err| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string())
                })?;
                Some(FileConfig::from_filepath(&filepath)?)
            }
            None => match FileConfig::from_default_filepath() {
                Ok(config) => Some(config),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => return Err(err),
            },
        };

        Self::from_configs(cli_cfg, file_cfg)
    }

    /// Creates a [node configuration](Configuration) by merging the options
    /// from the [CliConfig] and [FileConfig].
    ///
    /// Options from the [CliConfig] take precedence.
    ///
    /// Errors if a required option is not specified.
    fn from_configs(cli: CliConfig, file: Option<FileConfig>) -> std::io::Result<Self> {
        // Merge options, command-line takes precedence.
        let ethereum_rpc_url = cli.ethereum_rpc_url.or_else(|| match file {
            Some(cfg) => cfg.ethereum_rpc_url,
            None => None,
        });

        // Ethereum Endpoint is required.
        let ethereum_rpc_url = match ethereum_rpc_url {
            Some(endpoint) => endpoint,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Ethereum RPC endpoint is required",
                ))
            }
        };

        Ok(Self { ethereum_rpc_url })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_is_required() {
        // If other options become available, these should be set to something valid,
        // in order to test only the ethereum option.
        let cli = CliConfig {
            config_filepath: None,
            ethereum_rpc_url: None,
        };

        assert!(Configuration::from_configs(cli, None).is_err());
    }

    #[test]
    fn cli_takes_precedence() {
        let cli_url = "cli url";
        let cli = CliConfig {
            config_filepath: None,
            ethereum_rpc_url: Some(cli_url.to_owned()),
        };

        let file = FileConfig {
            ethereum_rpc_url: Some("file cli".to_owned()),
        };

        let expected = Configuration {
            ethereum_rpc_url: cli_url.to_owned(),
        };

        assert_eq!(
            Configuration::from_configs(cli, Some(file)).unwrap(),
            expected
        );
    }
}
