//! TOML configuration file parsing
use serde::Deserialize;

use crate::builder::ConfigBuilder;

#[derive(Deserialize, Debug, PartialEq)]
struct EthereumConfig {
    url: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
struct FileConfig {
    ethereum: Option<EthereumConfig>,
    #[serde(rename = "http-rpc")]
    http_rpc: Option<String>,
    #[serde(rename = "data-directory")]
    data_directory: Option<String>,
    #[serde(rename = "sequencer-url")]
    sequencer_url: Option<String>,
    #[serde(rename = "python-subprocesses")]
    python_subprocesses: Option<String>,
    #[serde(rename = "sqlite-wal")]
    sqlite_wal: Option<String>,
    #[serde(rename = "poll-pending")]
    poll_pending: Option<String>,
    #[serde(rename = "monitor-address")]
    monitor_address: Option<String>,
}

impl FileConfig {
    fn into_config_options(self) -> ConfigBuilder {
        use crate::ConfigOption;
        match self.ethereum {
            Some(eth) => ConfigBuilder::default()
                .with(ConfigOption::EthereumHttpUrl, eth.url)
                .with(ConfigOption::EthereumPassword, eth.password),
            None => ConfigBuilder::default(),
        }
        .with(ConfigOption::DataDirectory, self.data_directory)
        .with(ConfigOption::HttpRpcAddress, self.http_rpc)
        .with(ConfigOption::SequencerHttpUrl, self.sequencer_url)
        .with(ConfigOption::PythonSubprocesses, self.python_subprocesses)
        .with(ConfigOption::EnableSQLiteWriteAheadLogging, self.sqlite_wal)
        .with(ConfigOption::PollPending, self.poll_pending)
        .with(ConfigOption::MonitorAddress, self.monitor_address)
    }
}

/// Parses a [ConfigBuilder] from a toml format file.
pub fn config_from_filepath(filepath: &std::path::Path) -> std::io::Result<ConfigBuilder> {
    let file_contents = std::fs::read_to_string(filepath)?;
    config_from_str(&file_contents)
}

fn config_from_str(s: &str) -> std::io::Result<ConfigBuilder> {
    toml::from_str::<FileConfig>(s)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
        .map(|cfg| cfg.into_config_options())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConfigOption;

    #[test]
    fn ethereum_url() {
        let value = "value".to_owned();
        let toml = format!(r#"ethereum.url = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(value));
    }

    #[test]
    fn ethereum_password() {
        let value = "value".to_owned();
        let toml = format!(r#"ethereum.password = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(value));
    }

    #[test]
    fn ethereum_section() {
        let url = "url".to_owned();
        let password = "password".to_owned();

        let toml = format!(
            r#"[ethereum]
url = "{}"
password = "{}""#,
            url, password
        );

        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::EthereumHttpUrl), Some(url));
        assert_eq!(cfg.take(ConfigOption::EthereumPassword), Some(password));
    }

    #[test]
    fn http_rpc() {
        let value = "value".to_owned();
        let toml = format!(r#"http-rpc = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::HttpRpcAddress), Some(value));
    }

    #[test]
    fn data_directory() {
        let value = "value".to_owned();
        let toml = format!(r#"data-directory = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::DataDirectory), Some(value));
    }

    #[test]
    fn sequencer_url() {
        let value = "value".to_owned();
        let toml = format!(r#"sequencer-url = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::SequencerHttpUrl), Some(value));
    }

    #[test]
    fn python_subprocesses() {
        let value = "5".to_owned();
        let toml = format!(r#"python-subprocesses = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::PythonSubprocesses), Some(value));
    }

    #[test]
    fn sqlite_wal() {
        let value = "true".to_owned();
        let toml = format!(r#"sqlite-wal = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(
            cfg.take(ConfigOption::EnableSQLiteWriteAheadLogging),
            Some(value)
        );
    }

    #[test]
    fn poll_pending() {
        let value = "true".to_owned();
        let toml = format!(r#"poll-pending = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::PollPending), Some(value));
    }

    #[test]
    fn monitor_address() {
        let value = "address".to_owned();
        let toml = format!(r#"monitor-address = "{}""#, value);
        let mut cfg = config_from_str(&toml).unwrap();
        assert_eq!(cfg.take(ConfigOption::MonitorAddress), Some(value));
    }

    #[test]
    fn empty_config() {
        let cfg = config_from_str("").unwrap();
        assert_eq!(cfg, ConfigBuilder::default());
    }
}
