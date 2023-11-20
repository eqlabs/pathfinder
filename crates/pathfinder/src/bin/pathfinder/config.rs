use clap::{CommandFactory, Parser};
#[cfg(feature = "p2p")]
use p2p::libp2p::Multiaddr;
use pathfinder_common::AllowedOrigins;
use pathfinder_storage::JournalMode;
use reqwest::Url;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use pathfinder_common::consts::VERGEN_GIT_DESCRIBE;

#[derive(Parser)]
#[command(name = "Pathfinder")]
#[command(author = "Equilibrium Labs")]
#[command(version = VERGEN_GIT_DESCRIBE)]
#[command(
    about = "A Starknet node implemented by Equilibrium Labs. Submit bug reports and issues at https://github.com/eqlabs/pathfinder."
)]
struct Cli {
    #[arg(
        long,
        value_name = "DIR", 
        value_hint = clap::ValueHint::DirPath,
        long_help = "Directory where the node should store its data",
        env = "PATHFINDER_DATA_DIRECTORY", 
        default_value_os_t = (&std::path::Component::CurDir).into()
    )]
    data_directory: PathBuf,

    #[arg(
        long = "ethereum.password",
        long_help = "The optional password to use for the Ethereum API",
        value_name = None,
        env = "PATHFINDER_ETHEREUM_API_PASSWORD", 
    )]
    ethereum_password: Option<String>,

    #[arg(
        long = "ethereum.url",
        long_help = r"This should point to the HTTP RPC endpoint of your Ethereum entry-point, typically a local Ethereum client or a hosted gateway service such as Infura or Cloudflare.

Examples:
    infura: https://goerli.infura.io/v3/<PROJECT_ID>
    geth:   https://localhost:8545",
        value_name = "HTTP(s) URL",
        value_hint = clap::ValueHint::Url,
        env = "PATHFINDER_ETHEREUM_API_URL", 
    )]
    ethereum_url: Url,

    #[arg(
        long = "http-rpc",
        long_help = "HTTP-RPC listening address",
        value_name = "IP:PORT",
        default_value = "127.0.0.1:9545",
        env = "PATHFINDER_HTTP_RPC_ADDRESS"
    )]
    rpc_address: SocketAddr,

    #[arg(
        long = "rpc.cors-domains",
        long_help = r"Comma separated list of domains from which Cross-Origin requests will be accepted by the RPC server.

Use '*' to indicate any domain and an empty list to disable CORS.
        
Examples:
    single: http://one.io
    a list: http://first.com,http://second.com:1234
    any:    *",
        value_name = "DOMAIN LIST",
        value_delimiter = ',',
        env = "PATHFINDER_RPC_CORS_DOMAINS"
    )]
    rpc_cors_domains: Vec<String>,

    #[arg(
        long = "rpc.root-version",
        long_help = "Version of the JSON-RPC API to serve on the / (root) path",
        default_value = "v04",
        env = "PATHFINDER_RPC_ROOT_VERSION"
    )]
    rpc_root_version: RpcVersion,

    #[arg(
        long = "rpc.execution-concurrency",
        long_help = "The number of Cairo VM executors that can work concurrently. Defaults to the number of CPU cores available.",
        env = "PATHFINDER_RPC_EXECUTION_CONCURRENCY"
    )]
    execution_concurrency: Option<std::num::NonZeroU32>,

    #[arg(
        long = "monitor-address",
        long_help = "The address at which pathfinder will serve monitoring related information",
        value_name = "IP:PORT",
        env = "PATHFINDER_MONITOR_ADDRESS"
    )]
    monitor_address: Option<SocketAddr>,

    #[clap(flatten)]
    network: NetworkCli,

    /// poll_pending and p2p are mutually exclusive
    #[cfg(not(feature = "p2p"))]
    #[arg(
        long = "poll-pending",
        long_help = "Enable polling pending block",
        action = clap::ArgAction::Set,
        default_value = "false",
        env = "PATHFINDER_POLL_PENDING"
    )]
    poll_pending: bool,

    #[arg(
        long = "python-subprocesses",
        long_help = "This value is now unused and the argument was kept for compatibility reasons",
        default_value = "2",
        env = "PATHFINDER_PYTHON_SUBPROCESSES"
    )]
    python_subprocesses: std::num::NonZeroUsize,

    #[arg(
        long = "sqlite-wal",
        long_help = "Enable SQLite write-ahead logging",
        action = clap::ArgAction::Set,
        default_value = "true",
        env = "PATHFINDER_SQLITE_WAL", 
    )]
    sqlite_wal: bool,

    #[arg(
        long = "max-rpc-connections",
        long_help = "Set the maximum number of connections allowed",
        env = "PATHFINDER_MAX_RPC_CONNECTIONS",
        default_value = "1024"
    )]
    max_rpc_connections: std::num::NonZeroUsize,

    #[arg(
        long = "sync.poll-interval",
        long_help = "New block poll interval in seconds",
        default_value = "5",
        env = "PATHFINDER_HEAD_POLL_INTERVAL_SECONDS"
    )]
    poll_interval: std::num::NonZeroU64,

    #[arg(
        long = "color",
        long_help = "This flag controls when to use colors in the output logs.",
        default_value = "auto",
        env = "PATHFINDER_COLOR",
        value_name = "WHEN"
    )]
    color: Color,

    #[cfg(feature = "p2p")]
    #[clap(flatten)]
    p2p: P2PCli,

    #[cfg(not(feature = "p2p"))]
    #[clap(skip)]
    p2p: (),

    #[cfg(feature = "p2p")]
    #[clap(flatten)]
    debug: DebugCli,

    #[clap(flatten)]
    websocket: WebsocketConfig,

    #[cfg(not(feature = "p2p"))]
    #[clap(skip)]
    debug: (),

    #[arg(
        long = "sync.verify_tree_node_data",
        long_help = r"When enabled, state tree node hashes are verified when loaded from disk.

This can be used to identify tree node data corruption which is useful when debugging a state commitment mismatch.

This should only be enabled for debugging purposes as it adds substantial processing cost to every block.
",
        default_value = "false",
        env = "PATHFINDER_VERIFY_TREE_NODE_HASHES",
        value_name = "BOOL"
    )]
    verify_tree_node_data: bool,

    #[arg(
        long = "rpc.batch-concurrency-limit",
        long_help = "Sets the concurrency limit for request batch processing. \
            May lower the latency for large batches. \
            ⚠ While the response order is eventually preserved, execution may be performed out of \
            order.\
            Setting this to 1 effectively disables concurrency.",
        env = "PATHFINDER_RPC_BATCH_CONCURRENCY_LIMIT",
        default_value = "1"
    )]
    rpc_batch_concurrency_limit: NonZeroUsize,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq)]
pub enum Color {
    Auto,
    Never,
    Always,
}

impl Color {
    /// Returns true if color should be enabled, either because the setting is [Color::Always],
    /// or because it is [Color::Auto] and stdout is targeting a terminal.
    pub fn is_color_enabled(&self) -> bool {
        use std::io::IsTerminal;
        match self {
            Color::Auto => std::io::stdout().is_terminal(),
            Color::Never => false,
            Color::Always => true,
        }
    }
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq)]
pub enum RpcVersion {
    V03,
    V04,
    V05,
}

#[derive(clap::Args)]
struct NetworkCli {
    #[arg(
        long = "network",
        long_help = r"Specify the Starknet network for pathfinder to operate on.

Note that 'custom' requires also setting the --gateway-url and --feeder-gateway-url options.",
        value_enum,
        env = "PATHFINDER_NETWORK"
    )]
    network: Option<Network>,

    #[arg(
        long,
        long_help = "Set a custom Starknet chain ID (e.g. SN_GOERLI)",
        value_name = "CHAIN ID",
        env = "PATHFINDER_CHAIN_ID",
        required_if_eq("network", Network::Custom)
    )]
    chain_id: Option<String>,
    #[arg(
        long = "feeder-gateway-url",
        value_name = "URL",
        value_hint = clap::ValueHint::Url,
        long_help = "Specify a custom Starknet feeder gateway url. Can be used to run pathfinder on a custom Starknet network, or to use a gateway proxy. Requires '--network custom'.",
        env = "PATHFINDER_FEEDER_GATEWAY_URL", 
        required_if_eq("network", Network::Custom),
    )]
    feeder_gateway: Option<Url>,

    #[arg(
        long = "gateway-url",
        value_name = "URL",
        value_hint = clap::ValueHint::Url,
        long_help = "Specify a custom Starknet gateway url. Can be used to run pathfinder on a custom Starknet network, or to use a gateway proxy. Requires '--network custom'.",
        env = "PATHFINDER_GATEWAY_URL",
        required_if_eq("network", Network::Custom),
    )]
    gateway: Option<Url>,
}

#[cfg(feature = "p2p")]
#[derive(clap::Args)]
struct P2PCli {
    #[arg(
        long = "p2p.proxy",
        long_help = "Enable syncing from feeder gateway and proxy to p2p network. Otherwise sync from p2p network, which is the default.",
        default_value = "false",
        action = clap::ArgAction::Set,
        env = "PATHFINDER_P2P_PROXY"
    )]
    proxy: bool,
    #[arg(
        long = "p2p.identity-config-file",
        long_help = "Path to file containing the private key of the node. If not provided, a new random key will be generated.",
        value_name = "PATH",
        env = "PATHFINDER_P2P_IDENTITY_CONFIG_FILE"
    )]
    identity_config_file: Option<std::path::PathBuf>,
    #[arg(
        long = "p2p.listen-on",
        long_help = "The multiaddress on which to listen for incoming p2p connections. If not provided, default route on randomly assigned port will be used.",
        value_name = "MULTIADDRESS",
        default_value = "/ip4/0.0.0.0/tcp/0",
        env = "PATHFINDER_P2P_LISTEN_ON"
    )]
    listen_on: Multiaddr,
    #[arg(
        long = "p2p.bootstrap-addresses",
        long_help = "Comma separated list of multiaddresses to use as bootstrap nodes. The list cannot be empty.",
        value_name = "MULTIADDRESS_LIST",
        env = "PATHFINDER_P2P_BOOTSTRAP_ADDRESSES"
    )]
    bootstrap_addresses: Vec<String>,
}

#[cfg(feature = "p2p")]
#[derive(clap::Args)]
struct DebugCli {
    #[arg(
        long = "debug.pretty-log",
        long_help = "Enable pretty logging, which is especially helpful when debugging p2p behavior",
        action = clap::ArgAction::Set,
        default_value = "false",
        env = "PATHFINDER_PRETTY_LOG",
    )]
    pretty_log: bool,

    #[arg(
        long = "debug.restart-delay",
        long_help = "L2 restart delay after failure, in seconds",
        action = clap::ArgAction::Set,
        default_value = "60",
        env = "PATHFINDER_RESTART_DELAY",
    )]
    restart_delay: u64,
}

#[derive(clap::ValueEnum, Clone)]
enum Network {
    Mainnet,
    Testnet,
    Testnet2,
    Integration,
    Custom,
}

impl From<Network> for clap::builder::OsStr {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Testnet2 => "testnet2",
            Network::Integration => "integration",
            Network::Custom => "custom",
        }
        .into()
    }
}

fn parse_cors(inputs: Vec<String>) -> Result<Option<AllowedOrigins>, RpcCorsDomainsParseError> {
    if inputs.is_empty() {
        return Ok(None);
    }

    if inputs.len() == 1 && inputs[0] == "*" {
        return Ok(Some(AllowedOrigins::Any));
    }

    if inputs.iter().any(|s| s == "*") {
        return Err(RpcCorsDomainsParseError::WildcardAmongOtherValues);
    }

    let valid_origins = inputs
        .into_iter()
        .map(|input| match url::Url::parse(&input) {
            // Valid URL but has to be limited to origin form, i.e. no path, query, trailing slash for default path etc.
            Ok(url) => {
                let origin = url.origin();

                if !origin.is_tuple() {
                    return Err(RpcCorsDomainsParseError::InvalidDomain(input));
                }

                if origin.ascii_serialization() == input {
                    Ok(input)
                } else {
                    // Valid URL but not a valid origin
                    Err(RpcCorsDomainsParseError::InvalidDomain(input))
                }
            }
            // Not an URL hence invalid origin
            Err(_e) => {
                eprintln!("Url_parse_error: {_e}");
                Err(RpcCorsDomainsParseError::InvalidDomain(input))
            }
        })
        .collect::<Result<HashSet<_>, RpcCorsDomainsParseError>>()?;

    Ok(Some(AllowedOrigins::List(
        valid_origins.into_iter().collect(),
    )))
}

pub fn parse_cors_or_exit(input: Vec<String>) -> Option<AllowedOrigins> {
    use clap::error::ErrorKind;

    match parse_cors(input) {
        Ok(parsed) => parsed,
        Err(error) => Cli::command()
            .error(ErrorKind::ValueValidation, error)
            .exit(),
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("Invalid domain for CORS: {0}")]
struct InvalidCorsDomainError(String);

#[derive(Debug, thiserror::Error, PartialEq)]
enum RpcCorsDomainsParseError {
    #[error("Invalid allowed domain for CORS: {0}.")]
    InvalidDomain(String),
    #[error(
        "Specify either wildcard '*' or a comma separated list of allowed domains for CORS, not both."
    )]
    WildcardAmongOtherValues,
}

pub struct Config {
    pub data_directory: PathBuf,
    pub ethereum: Ethereum,
    pub rpc_address: SocketAddr,
    pub rpc_cors_domains: Option<AllowedOrigins>,
    pub rpc_root_version: RpcVersion,
    pub websocket: WebsocketConfig,
    pub monitor_address: Option<SocketAddr>,
    pub network: Option<NetworkConfig>,
    pub poll_pending: bool,
    pub execution_concurrency: Option<std::num::NonZeroU32>,
    pub sqlite_wal: JournalMode,
    pub max_rpc_connections: std::num::NonZeroUsize,
    pub poll_interval: std::time::Duration,
    pub color: Color,
    pub p2p: P2PConfig,
    pub debug: DebugConfig,
    pub verify_tree_hashes: bool,
    pub rpc_batch_concurrency_limit: NonZeroUsize,
}

pub struct Ethereum {
    pub url: Url,
    pub password: Option<String>,
}

pub enum NetworkConfig {
    Mainnet,
    Testnet,
    Testnet2,
    Integration,
    Custom {
        gateway: Url,
        feeder_gateway: Url,
        chain_id: String,
    },
}

#[cfg(feature = "p2p")]
pub struct P2PConfig {
    pub proxy: bool,
    pub identity_config_file: Option<std::path::PathBuf>,
    pub listen_on: Multiaddr,
    pub bootstrap_addresses: Vec<Multiaddr>,
}

#[cfg(not(feature = "p2p"))]
pub struct P2PConfig;

pub struct DebugConfig {
    pub pretty_log: bool,
    pub restart_delay: std::time::Duration,
}

impl NetworkConfig {
    fn from_components(args: NetworkCli) -> Option<Self> {
        use Network::*;
        let cfg = match (
            args.network,
            args.gateway,
            args.feeder_gateway,
            args.chain_id,
        ) {
            (None, None, None, None) => return None,
            (Some(Custom), Some(gateway), Some(feeder_gateway), Some(chain_id)) => {
                NetworkConfig::Custom {
                    gateway,
                    feeder_gateway,
                    chain_id,
                }
            }
            (Some(Custom), _, _, _) => {
                unreachable!("`--network custom` requirements are handled by clap derive")
            }
            // Handle non-custom variants in an inner match so that the compiler will force
            // us to handle a new network variants explicitly. Otherwise we end up with a
            // catch-all arm that would swallow new variants silently.
            (Some(non_custom), None, None, None) => match non_custom {
                Mainnet => NetworkConfig::Mainnet,
                Testnet => NetworkConfig::Testnet,
                Testnet2 => NetworkConfig::Testnet2,
                Integration => NetworkConfig::Integration,
                Custom => unreachable!("Network::Custom handled in outer arm already"),
            },
            // clap does not support disallowing args based on an enum value, so we have check for
            // `--network non-custom` + custom required args manually.
            _ => {
                use clap::error::ErrorKind;

                Cli::command().error(ErrorKind::ArgumentConflict, "--gateway-url, --feeder-gateway-url and --chain-id may only be used with --network custom").exit()
            }
        };

        Some(cfg)
    }
}

#[cfg(not(feature = "p2p"))]
impl P2PConfig {
    fn parse_or_exit(_: ()) -> Self {
        Self
    }
}

#[cfg(feature = "p2p")]
impl P2PConfig {
    fn parse_or_exit(args: P2PCli) -> Self {
        use clap::error::ErrorKind;
        use p2p::libp2p::multiaddr::Result;
        use std::str::FromStr;

        Self {
            proxy: args.proxy,
            identity_config_file: args.identity_config_file,
            listen_on: args.listen_on,
            bootstrap_addresses: {
                let x = args
                    .bootstrap_addresses
                    .into_iter()
                    .map(|addr| Multiaddr::from_str(&addr))
                    .collect::<Result<Vec<_>>>()
                    .unwrap_or_else(|error| {
                        Cli::command()
                            .error(ErrorKind::ValueValidation, error)
                            .exit()
                    });
                x.is_empty().then(|| {
                    Cli::command()
                        .error(
                            ErrorKind::ValueValidation,
                            "Specify at least one bootstrap address.",
                        )
                        .exit()
                });
                x
            },
        }
    }
}

#[cfg(not(feature = "p2p"))]
impl DebugConfig {
    fn parse(_: ()) -> Self {
        Self {
            pretty_log: false,
            restart_delay: std::time::Duration::from_secs(60),
        }
    }
}

#[cfg(feature = "p2p")]
impl DebugConfig {
    fn parse(args: DebugCli) -> Self {
        Self {
            pretty_log: args.pretty_log,
            restart_delay: std::time::Duration::from_secs(args.restart_delay),
        }
    }
}

impl Config {
    pub fn parse() -> Self {
        let cli = Cli::parse();

        let network = NetworkConfig::from_components(cli.network);

        Config {
            data_directory: cli.data_directory,
            ethereum: Ethereum {
                password: cli.ethereum_password,
                url: cli.ethereum_url,
            },
            rpc_address: cli.rpc_address,
            rpc_cors_domains: parse_cors_or_exit(cli.rpc_cors_domains),
            rpc_root_version: cli.rpc_root_version,
            websocket: cli.websocket,
            monitor_address: cli.monitor_address,
            network,
            #[cfg(feature = "p2p")]
            poll_pending: false,
            #[cfg(not(feature = "p2p"))]
            poll_pending: cli.poll_pending,
            execution_concurrency: cli.execution_concurrency,
            sqlite_wal: match cli.sqlite_wal {
                true => JournalMode::WAL,
                false => JournalMode::Rollback,
            },
            max_rpc_connections: cli.max_rpc_connections,
            poll_interval: std::time::Duration::from_secs(cli.poll_interval.get()),
            color: cli.color,
            p2p: P2PConfig::parse_or_exit(cli.p2p),
            debug: DebugConfig::parse(cli.debug),
            verify_tree_hashes: cli.verify_tree_node_data,
            rpc_batch_concurrency_limit: cli.rpc_batch_concurrency_limit,
        }
    }
}

#[derive(clap::Args, Clone)]
pub struct WebsocketConfig {
    #[arg(
        long = "rpc.websocket.enabled",
        long_help = "Enable RPC WebSocket transport at the \"/ws\" path",
        default_value = "false",
        env = "PATHFINDER_WEBSOCKET_ENABLED"
    )]
    pub enabled: bool,
    #[arg(
        long = "rpc.websocket.buffer-capacity",
        long_help = "The socket buffer for outbound messages. If specific clients have their \
            subscription sporadically closed due to lagging streams, consider increasing this \
            buffer. See also `rpc.websocket.topic-capacity`",
        value_name = "CAPACITY",
        default_value = "100",
        env = "PATHFINDER_WEBSOCKET_BUFFER_CAPACITY"
    )]
    pub socket_buffer_capacity: NonZeroUsize,
    #[arg(
        long = "rpc.websocket.topic-capacity",
        long_help = "The topic sender capacity. The topic senders are upstream of socket buffers \
            and common to all clients and subscriptions. If a variety of clients regularly have their \
            subscription closed due to a lagging stream, consider increasing this buffer. See also \
            `rpc.websocket.buffer-capacity`",
        value_name = "CAPACITY",
        default_value = "100",
        env = "PATHFINDER_WEBSOCKET_TOPIC_CAPACITY"
    )]
    pub topic_sender_capacity: NonZeroUsize,
}

#[cfg(test)]
mod tests {
    use super::{AllowedOrigins, RpcCorsDomainsParseError};
    use crate::config::parse_cors;

    #[test]
    fn parse_cors_domains() {
        let empty = String::new();
        let wildcard = "*".to_owned();
        let valid = "http://valid.com:1234".to_owned();
        let not_url = "not_url".to_string();
        let with_path = "http://a.com/path".to_string();
        let with_query = "http://a.com/?query=x".to_string();
        let with_trailing_slash = format!("{valid}/");

        [
            (
                vec![empty.clone()],
                RpcCorsDomainsParseError::InvalidDomain(empty.clone()),
            ),
            (
                vec![empty, wildcard.clone()],
                RpcCorsDomainsParseError::WildcardAmongOtherValues,
            ),
            (
                vec![valid.clone(), wildcard.clone()],
                RpcCorsDomainsParseError::WildcardAmongOtherValues,
            ),
            (
                vec![wildcard.clone(), wildcard.clone()],
                RpcCorsDomainsParseError::WildcardAmongOtherValues,
            ),
            (
                vec![valid.clone(), with_trailing_slash.clone()],
                RpcCorsDomainsParseError::InvalidDomain(with_trailing_slash),
            ),
            (
                vec![valid.clone(), not_url.clone()],
                RpcCorsDomainsParseError::InvalidDomain(not_url),
            ),
            (
                vec![valid.clone(), with_path.clone()],
                RpcCorsDomainsParseError::InvalidDomain(with_path),
            ),
            (
                vec![valid.clone(), with_query.clone()],
                RpcCorsDomainsParseError::InvalidDomain(with_query),
            ),
        ]
        .into_iter()
        .for_each(|(input, expected_error)| {
            assert_eq!(
                parse_cors(input.clone()).unwrap_err(),
                expected_error,
                "input: {input:?}"
            );
        });

        [
            (vec![], None),
            (vec![wildcard], Some(AllowedOrigins::Any)),
            (
                vec![valid.clone()],
                Some(AllowedOrigins::List(vec![valid.clone()])),
            ),
            (
                vec![valid.clone(), valid.clone()],
                Some(AllowedOrigins::List(vec![valid])),
            ),
        ]
        .into_iter()
        .for_each(|(input, expected_ok)| {
            assert_eq!(
                parse_cors(input.clone()).unwrap(),
                expected_ok,
                "input: {input:?}"
            )
        });
    }
}
