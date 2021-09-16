//! Command-line argument parsing
use clap::{crate_version, Arg};
use std::ffi::OsString;

/// Supported command-line options.
#[derive(Debug, PartialEq)]
pub struct CliConfig {
    /// Path to the configuration file.
    pub config_filepath: Option<String>,
    /// The Ethereum RPC endpoint.
    pub ethereum_rpc_url: Option<String>,
}

impl CliConfig {
    /// Creates a [CliConfig] from the command-line arguments.
    ///
    /// Note: This will terminate the program if invalid arguments are supplied.
    ///       This is intended, as [clap] will show the program usage / help.
    pub fn parse_cmd_line() -> Self {
        // A thin wrapper around `parse_args()`. This should be kept thin
        // to enable test coverage without requiring cmd line arg input.
        match Self::parse_args(&mut std::env::args_os()) {
            Ok(cfg) => cfg,
            Err(err) => err.exit(),
        }
    }

    /// A wrapper around [clap::App]'s `get_matches_from_safe()` which returns
    /// a [CliConfig].
    fn parse_args<I, T>(args: I) -> clap::Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let args = Self::clap_app().get_matches_from_safe(args)?;

        let config_filepath = args.value_of("config").map(|s| s.to_owned());
        let ethereum_rpc_url = args.value_of("ethereum").map(|s| s.to_owned());

        Ok(Self {
            config_filepath,
            ethereum_rpc_url,
        })
    }

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
                Arg::with_name("config")
                    .short("c")
                    .long("config")
                    .help("Path to the configuration file")
                    .long_help(
                        &CFG_LONG_HELP,
                    )
                    .value_name("FILE")
                    .takes_value(true),
            )
            .arg(Arg::with_name("ethereum").short("e").long("ethereum").help("Ethereum API URL").takes_value(true).value_name("URL")
            .long_help(
r#"This should point to the RPC endpoint of your Ethereum entry-point, typically a local Ethereum light client or a hosted gateway service such as Infura or Cloudflare.

Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   127.0.0.1:8545"#))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ethereum_endpoint_short() {
        let value = "value".to_owned();
        let cfg = CliConfig::parse_args(vec!["bin name", "-e", &value]).unwrap();
        assert_eq!(cfg.ethereum_rpc_url, Some(value));
    }

    #[test]
    fn ethereum_endpoint_long() {
        let value = "value".to_owned();
        let cfg = CliConfig::parse_args(vec!["bin name", "--ethereum", &value]).unwrap();
        assert_eq!(cfg.ethereum_rpc_url, Some(value));
    }

    #[test]
    fn config_filepath_short() {
        let value = "value".to_owned();
        let cfg = CliConfig::parse_args(vec!["bin name", "-c", &value]).unwrap();
        assert_eq!(cfg.config_filepath, Some(value));
    }

    #[test]
    fn config_filepath_long() {
        let value = "value".to_owned();
        let cfg = CliConfig::parse_args(vec!["bin name", "--config", &value]).unwrap();
        assert_eq!(cfg.config_filepath, Some(value));
    }

    #[test]
    fn empty_config() {
        let cfg = CliConfig::parse_args(vec!["bin name"]).unwrap();

        assert_eq!(
            cfg,
            CliConfig {
                config_filepath: None,
                ethereum_rpc_url: None,
            }
        );
    }
}
