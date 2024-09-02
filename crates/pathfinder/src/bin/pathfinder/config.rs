use std::collections::HashSet;
use std::fs::File;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgAction, CommandFactory, Parser};
#[cfg(feature = "p2p")]
use ipnet::IpNet;
#[cfg(feature = "p2p")]
use p2p::libp2p::Multiaddr;
use pathfinder_common::consts::VERGEN_GIT_DESCRIBE;
use pathfinder_common::AllowedOrigins;
use pathfinder_executor::VersionedConstants;
use pathfinder_storage::JournalMode;
use reqwest::Url;

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
    infura: https://mainnet.infura.io/v3/<PROJECT_ID>
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
        default_value = "v06",
        env = "PATHFINDER_RPC_ROOT_VERSION"
    )]
    rpc_root_version: RpcVersion,

    #[arg(
        long = "rpc.execution-concurrency",
        long_help = "The number of Cairo VM executors that can work concurrently. Defaults to the \
                     number of CPU cores available.",
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
        default_value = "2",
        env = "PATHFINDER_HEAD_POLL_INTERVAL_SECONDS"
    )]
    poll_interval: std::num::NonZeroU64,

    #[arg(
        long = "sync.l1-poll-interval",
        long_help = "L1 state poll interval in seconds",
        default_value = "30",
        env = "PATHFINDER_L1_POLL_INTERVAL_SECONDS"
    )]
    l1_poll_interval: std::num::NonZeroU64,

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
        long_help = "Sets the concurrency limit for request batch processing. May lower the \
                     latency for large batches. ⚠ While the response order is eventually \
                     preserved, execution may be performed out of order.Setting this to 1 \
                     effectively disables concurrency.",
        env = "PATHFINDER_RPC_BATCH_CONCURRENCY_LIMIT",
        default_value = "1"
    )]
    rpc_batch_concurrency_limit: NonZeroUsize,

    #[arg(
        long = "sync.enable",
        long_help = "Enable syncing the chain",
        env = "PATHFINDER_SYNC_ENABLED",
        default_value = "true",
        action=ArgAction::Set
    )]
    is_sync_enabled: bool,

    #[arg(
        long = "rpc.enable",
        long_help = "Enable serving RPC API",
        env = "PATHFINDER_RPC_ENABLED",
        default_value = "true",
        action=ArgAction::Set
    )]
    is_rpc_enabled: bool,

    #[arg(
        long = "gateway-api-key",
        value_name = "API_KEY",
        long_help = "Specify an API key for both the Starknet feeder gateway and gateway.",
        env = "PATHFINDER_GATEWAY_API_KEY"
    )]
    gateway_api_key: Option<String>,

    #[arg(
        long = "gateway.request-timeout",
        value_name = "Seconds",
        long_help = "Timeout duration for all gateway and feeder-gateway requests",
        env = "PATHFINDER_GATEWAY_REQUEST_TIMEOUT",
        default_value = "5"
    )]
    gateway_timeout: std::num::NonZeroU64,

    #[arg(
        long = "gateway.fetch-concurrency",
        long_help = "How many concurrent requests to send to the feeder gateway when fetching \
                     block data",
        env = "PATHFINDER_GATEWAY_FETCH_CONCURRENCY",
        default_value = "8"
    )]
    feeder_gateway_fetch_concurrency: std::num::NonZeroUsize,

    #[arg(
        long = "storage.event-bloom-filter-cache-size",
        long_help = "The number of blocks whose event bloom filters are cached in memory. This \
                     cache speeds up event related RPC queries at the cost of using extra memory. \
                     Each cached filter takes 2 KiB of memory.",
        env = "PATHFINDER_STORAGE_BLOOM_FILTER_CACHE_SIZE",
        default_value = "524288"
    )]
    event_bloom_filter_cache_size: std::num::NonZeroUsize,

    #[arg(
        long = "rpc.get-events-max-blocks-to-scan",
        long_help = "The number of blocks to scan for events when querying for events. This limit \
                     is used to prevent queries from taking too long.",
        env = "PATHFINDER_RPC_GET_EVENTS_MAX_BLOCKS_TO_SCAN",
        default_value = "500"
    )]
    get_events_max_blocks_to_scan: std::num::NonZeroUsize,

    #[arg(
        long = "rpc.get-events-max-uncached-bloom-filters-to-load",
        long_help = "The number of Bloom filters to load for events when querying for events. \
                     This limit is used to prevent queries from taking too long.",
        env = "PATHFINDER_RPC_GET_EVENTS_MAX_UNCACHED_BLOOM_FILTERS_TO_LOAD",
        default_value = "100000"
    )]
    get_events_max_uncached_bloom_filters_to_load: std::num::NonZeroUsize,

    #[arg(
        long = "storage.state-tries",
        long_help = "When set to `archive` all historical Merkle trie state is preserved. When set to an integer N, only the last N+1 states of the Merkle tries are kept in the database. \
            This can be used to reduce the disk space usage at the cost of only being able to provide storage proofs for the latest N+1 blocks (the state for the latest block is always stored). \
            Defaults to 20 if the database was created with pruning enabled or `archive` if the database is archive-mode.",
        env = "PATHFINDER_STORAGE_STATE_TRIES",
        value_name = "archive | N",
        value_parser = parse_state_tries
    )]
    state_tries: Option<StateTries>,

    #[arg(
        long = "rpc.custom-versioned-constants-json-path",
        long_help = "Path to a JSON file containing the versioned constants to use for execution",
        env = "PATHFINDER_RPC_CUSTOM_VERSIONED_CONSTANTS_JSON_PATH"
    )]
    custom_versioned_constants_path: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq)]
pub enum Color {
    Auto,
    Never,
    Always,
}

impl Color {
    /// Returns true if color should be enabled, either because the setting is
    /// [Color::Always], or because it is [Color::Auto] and stdout is
    /// targeting a terminal.
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
    V06,
    V07,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StateTries {
    Pruned(u64),
    Archive,
}

fn parse_state_tries(s: &str) -> Result<StateTries, String> {
    match s {
        "archive" => Ok(StateTries::Archive),
        _ => {
            let value: u64 = s
                .parse()
                .map_err(|_| "Expected either `archive` or a number".to_string())?;
            Ok(StateTries::Pruned(value))
        }
    }
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
        long_help = "Set a custom Starknet chain ID (e.g. SN_SEPOLIA)",
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
        long_help = "Path to file containing the private key of the node. If not provided, a new \
                     random key will be generated.",
        value_name = "PATH",
        env = "PATHFINDER_P2P_IDENTITY_CONFIG_FILE"
    )]
    identity_config_file: Option<std::path::PathBuf>,
    #[arg(
        long = "p2p.listen-on",
        long_help = "The multiaddress on which to listen for incoming p2p connections. If not \
                     provided, default route on randomly assigned port will be used.",
        value_name = "MULTIADDRESS",
        default_value = "/ip4/0.0.0.0/tcp/0",
        env = "PATHFINDER_P2P_LISTEN_ON"
    )]
    listen_on: Multiaddr,
    #[arg(
        long = "p2p.bootstrap-addresses",
        long_help = r#"Comma separated list of multiaddresses to use as bootstrap nodes. Each multiaddress must contain a peer ID.

Example:
    '/ip4/127.0.0.1/9001/p2p/12D3KooWBEkKyufuqCMoZLRhVzq4xdHxVWhhYeBpjw92GSyZ6xaN,/ip4/127.0.0.1/9002/p2p/12D3KooWBEkKyufuqCMoZLRhVzq4xdHxVWhhYeBpjw92GSyZ6xaN'"#,
        value_name = "MULTIADDRESS_LIST",
        value_delimiter = ',',
        env = "PATHFINDER_P2P_BOOTSTRAP_ADDRESSES"
    )]
    bootstrap_addresses: Vec<String>,

    #[arg(
        long = "p2p.predefined-peers",
        long_help = r#"Comma separated list of multiaddresses to use as peers apart from peers discovered via DHT discovery. Each multiaddress must contain a peer ID.

Example:
    '/ip4/127.0.0.1/9003/p2p/12D3KooWBEkKyufuqCMoZLRhVzq4xdHxVWhhYeBpjw92GSyZ6xaP,/ip4/127.0.0.1/9004/p2p/12D3KooWBEkKyufuqCMoZLRhVzq4xdHxVWhhYeBpjw92GSyZ6xaR'"#,
        value_name = "MULTIADDRESS_LIST",
        value_delimiter = ',',
        env = "PATHFINDER_P2P_PREDEFINED_PEERS"
    )]
    predefined_peers: Vec<String>,

    #[arg(
        long = "p2p.max-inbound-direct-connections",
        long_help = "The maximum number of inbound direct (non-relayed) connections.",
        value_name = "MAX_INBOUND_DIRECT_CONNECTIONS",
        env = "PATHFINDER_MAX_INBOUND_DIRECT_CONNECTIONS",
        default_value = "30"
    )]
    max_inbound_direct_connections: u32,

    #[arg(
        long = "p2p.max-inbound-relayed-connections",
        long_help = "The maximum number of inbound relayed connections.",
        value_name = "MAX_INBOUND_RELAYED_CONNECTIONS",
        env = "PATHFINDER_MAX_INBOUND_RELAYED_CONNECTIONS",
        default_value = "30"
    )]
    max_inbound_relayed_connections: u32,

    #[arg(
        long = "p2p.max-outbound-connections",
        long_help = "The maximum number of outbound connections.",
        value_name = "MAX_OUTBOUND_CONNECTIONS",
        env = "PATHFINDER_MAX_OUTBOUND_CONNECTIONS",
        default_value = "50"
    )]
    max_outbound_connections: u32,

    #[arg(
        long = "p2p.low-watermark",
        long_help = "The minimum number of outbound peers to maintain. If the number of outbound \
                     peers drops below this number, the node will attempt to connect to more \
                     peers.",
        value_name = "LOW_WATERMARK",
        env = "PATHFINDER_LOW_WATERMARK",
        default_value = "20"
    )]
    low_watermark: u32,

    #[arg(
        long = "p2p.ip-whitelist",
        long_help = "Comma separated list of IP addresses or IP address ranges (in CIDR) to \
                     whitelist for incoming connections. If not provided, all incoming \
                     connections are allowed.",
        value_name = "LIST",
        default_value = "0.0.0.0/0,::/0",
        value_delimiter = ',',
        env = "IP_WHITELIST"
    )]
    ip_whitelist: Vec<IpNet>,

    #[arg(
        long = "p2p.experimental.kad-names",
        long_help = "Comma separated list of custom Kademlia protocol names.",
        value_name = "LIST",
        value_delimiter = ',',
        env = "PATHFINDER_P2P_EXPERIMENTAL_KAD_NAMES"
    )]
    kad_names: Vec<String>,

    #[arg(
        long = "p2p.experimental.l1-checkpoint-override-json-path",
        long_help = "Override L1 sync checkpoint retrieved from the Ethereum API. This option \
                     points to a json encoded file containing an L1 checkpoint from which \
                     pathfinder will sync backwards till genesis before switching to syncing \
                     forward and following the head of the chain. Example contents: { \
                     \"block_hash\": \"0x1\", \"block_number\": 2, \"state_root\": \"0x3\" }",
        value_name = "JSON_FILE",
        env = "PATHFINDER_P2P_EXPERIMENTAL_L1_CHECKPOINT_OVERRIDE"
    )]
    l1_checkpoint_override: Option<String>,

    #[arg(
        long = "p2p.experimental.stream-timeout",
        long_help = "Timeout of the request/response-stream protocol.",
        value_name = "SECONDS",
        default_value = "60",
        env = "PATHFINDER_P2P_EXPERIMENTAL_STREAM_TIMEOUT"
    )]
    stream_timeout: u32,

    #[arg(
        long = "p2p.experimental.max-concurrent-streams",
        long_help = "Maximum allowed number of concurrent streams per each \
                     request/response-stream protocol.",
        value_name = "LIMIT",
        default_value = "100",
        env = "PATHFINDER_P2P_EXPERIMENTAL_MAX_CONCURRENT_STREAMS"
    )]
    max_concurrent_streams: usize,

    #[arg(
        long = "p2p.experimental.direct-connection-timeout",
        long_help = "A direct (not relayed) peer can only connect once in this period.",
        value_name = "SECONDS",
        default_value = "30",
        env = "PATHFINDER_P2P_EXPERIMENTAL_DIRECT_CONNECTION_TIMEOUT"
    )]
    direct_connection_timeout: u32,

    #[arg(
        long = "p2p.experimental.eviction-timeout",
        long_help = "How long to prevent evicted peers from reconnecting.",
        value_name = "SECONDS",
        default_value = "900",
        env = "PATHFINDER_P2P_EXPERIMENTAL_EVICTION_TIMEOUT"
    )]
    eviction_timeout: u32,
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

#[derive(clap::ValueEnum, Clone, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Network {
    Mainnet,
    SepoliaTestnet,
    SepoliaIntegration,
    Custom,
}

impl From<Network> for clap::builder::OsStr {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => "mainnet",
            Network::SepoliaTestnet => "sepolia-testnet",
            Network::SepoliaIntegration => "sepolia-integration",
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
            // Valid URL but has to be limited to origin form, i.e. no path, query, trailing slash
            // for default path etc.
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
enum RpcCorsDomainsParseError {
    #[error("Invalid allowed domain for CORS: {0}.")]
    InvalidDomain(String),
    #[error(
        "Specify either wildcard '*' or a comma separated list of allowed domains for CORS, not \
         both."
    )]
    WildcardAmongOtherValues,
}

fn parse_versioned_constants(
    path: PathBuf,
) -> Result<VersionedConstants, ParseVersionedConstantsError> {
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let versioned_constants = serde_json::from_reader(reader)?;

    Ok(versioned_constants)
}

pub fn parse_versioned_constants_or_exit(path: PathBuf) -> VersionedConstants {
    use clap::error::ErrorKind;

    match parse_versioned_constants(path) {
        Ok(versioned_constants) => versioned_constants,
        Err(error) => Cli::command()
            .error(ErrorKind::ValueValidation, error)
            .exit(),
    }
}

#[derive(Debug, thiserror::Error)]
enum ParseVersionedConstantsError {
    #[error("IO error while reading versioned constants: {0}.")]
    Io(#[from] std::io::Error),
    #[error("Parse error while loading versioned constants: {0}.")]
    Parse(#[from] serde_json::Error),
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
    pub execution_concurrency: Option<std::num::NonZeroU32>,
    pub sqlite_wal: JournalMode,
    pub max_rpc_connections: std::num::NonZeroUsize,
    pub poll_interval: std::time::Duration,
    pub l1_poll_interval: std::time::Duration,
    pub color: Color,
    pub p2p: P2PConfig,
    pub debug: DebugConfig,
    pub verify_tree_hashes: bool,
    pub rpc_batch_concurrency_limit: NonZeroUsize,
    pub is_sync_enabled: bool,
    pub is_rpc_enabled: bool,
    pub gateway_api_key: Option<String>,
    pub gateway_timeout: Duration,
    pub event_bloom_filter_cache_size: NonZeroUsize,
    pub get_events_max_blocks_to_scan: NonZeroUsize,
    pub get_events_max_uncached_bloom_filters_to_load: NonZeroUsize,
    pub state_tries: Option<StateTries>,
    pub custom_versioned_constants: Option<VersionedConstants>,
    pub feeder_gateway_fetch_concurrency: NonZeroUsize,
}

pub struct Ethereum {
    pub url: Url,
    pub password: Option<String>,
}

#[derive(Clone)]
pub enum NetworkConfig {
    Mainnet,
    SepoliaTestnet,
    SepoliaIntegration,
    Custom {
        gateway: Url,
        feeder_gateway: Url,
        chain_id: String,
    },
}

#[cfg(feature = "p2p")]
#[derive(Clone)]
pub struct P2PConfig {
    pub proxy: bool,
    pub identity_config_file: Option<std::path::PathBuf>,
    pub listen_on: Multiaddr,
    pub bootstrap_addresses: Vec<Multiaddr>,
    pub predefined_peers: Vec<Multiaddr>,
    pub max_inbound_direct_connections: usize,
    pub max_inbound_relayed_connections: usize,
    pub max_outbound_connections: usize,
    pub ip_whitelist: Vec<IpNet>,
    pub low_watermark: usize,
    pub kad_names: Vec<String>,
    pub l1_checkpoint_override: Option<pathfinder_ethereum::EthereumStateUpdate>,
    pub stream_timeout: Duration,
    pub max_concurrent_streams: usize,
    pub direct_connection_timeout: Duration,
    pub eviction_timeout: Duration,
}

#[cfg(not(feature = "p2p"))]
#[derive(Clone)]
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
                SepoliaTestnet => NetworkConfig::SepoliaTestnet,
                SepoliaIntegration => NetworkConfig::SepoliaIntegration,
                Custom => unreachable!("Network::Custom handled in outer arm already"),
            },
            // clap does not support disallowing args based on an enum value, so we have check for
            // `--network non-custom` + custom required args manually.
            _ => {
                use clap::error::ErrorKind;

                Cli::command()
                    .error(
                        ErrorKind::ArgumentConflict,
                        "--gateway-url, --feeder-gateway-url and --chain-id may only be used with \
                         --network custom",
                    )
                    .exit()
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
        use std::str::FromStr;

        use clap::error::ErrorKind;
        use p2p::libp2p::multiaddr::Result;

        let parse_multiaddr_vec = |field: &str, multiaddrs: Vec<String>| -> Vec<Multiaddr> {
            multiaddrs
                .into_iter()
                .map(|addr| Multiaddr::from_str(&addr))
                .collect::<Result<Vec<_>>>()
                .unwrap_or_else(|error| {
                    Cli::command()
                        .error(ErrorKind::ValueValidation, format!("{field}: {error}"))
                        .exit()
                })
        };

        if (1..25).contains(&args.max_inbound_direct_connections) {
            Cli::command()
                .error(
                    ErrorKind::ValueValidation,
                    "p2p.max-inbound-direct-connections must be zero or at least 25",
                )
                .exit()
        }

        if (1..25).contains(&args.max_inbound_relayed_connections) {
            Cli::command()
                .error(
                    ErrorKind::ValueValidation,
                    "p2p.max-inbound-relayed-connections must be zero or at least 25",
                )
                .exit()
        }

        if args.low_watermark > args.max_outbound_connections {
            Cli::command()
                .error(
                    ErrorKind::ValueValidation,
                    "p2p.low-watermark must be less than or equal to p2p.max_outbound_connections",
                )
                .exit()
        }

        if args.kad_names.iter().any(|x| !x.starts_with('/')) {
            Cli::command()
                .error(
                    ErrorKind::ValueValidation,
                    "each item in p2p.experimental.kad-names must start with '/'",
                )
                .exit()
        }

        let l1_checkpoint_override = parse_l1_checkpoint_or_exit(args.l1_checkpoint_override);

        Self {
            max_inbound_direct_connections: args.max_inbound_direct_connections.try_into().unwrap(),
            max_inbound_relayed_connections: args
                .max_inbound_relayed_connections
                .try_into()
                .unwrap(),
            max_outbound_connections: args.max_outbound_connections.try_into().unwrap(),
            proxy: args.proxy,
            identity_config_file: args.identity_config_file,
            listen_on: args.listen_on,
            bootstrap_addresses: parse_multiaddr_vec(
                "p2p.bootstrap-addresses",
                args.bootstrap_addresses,
            ),
            predefined_peers: parse_multiaddr_vec("p2p.predefined-peers", args.predefined_peers),
            ip_whitelist: args.ip_whitelist,
            low_watermark: 0,
            kad_names: args.kad_names,
            l1_checkpoint_override,
            stream_timeout: Duration::from_secs(args.stream_timeout.into()),
            max_concurrent_streams: args.max_concurrent_streams,
            direct_connection_timeout: Duration::from_secs(args.direct_connection_timeout.into()),
            eviction_timeout: Duration::from_secs(args.eviction_timeout.into()),
        }
    }
}

#[cfg(feature = "p2p")]
fn parse_l1_checkpoint_or_exit(
    l1_checkpoint_override: Option<String>,
) -> Option<pathfinder_ethereum::EthereumStateUpdate> {
    use clap::error::ErrorKind;
    use pathfinder_common::{BlockHash, BlockNumber, StateCommitment};

    #[derive(serde::Deserialize)]
    struct Dto {
        state_root: StateCommitment,
        block_number: BlockNumber,
        block_hash: BlockHash,
    }

    fn exit_now(e: impl std::fmt::Display) {
        Cli::command()
            .error(
                ErrorKind::ValueValidation,
                format!("p2p.experimental.l1-checkpoint-override: {e}"),
            )
            .exit()
    }

    l1_checkpoint_override.map(|f| {
        // SAFETY: unwraps are safe because we exit the process on error
        let f = std::fs::File::open(f).map_err(exit_now).unwrap();
        let dto: Dto = serde_json::from_reader(f).map_err(exit_now).unwrap();
        pathfinder_ethereum::EthereumStateUpdate {
            state_root: dto.state_root,
            block_number: dto.block_number,
            block_hash: dto.block_hash,
        }
    })
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
    #[cfg_attr(not(feature = "p2p"), allow(clippy::unit_arg))]
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
            execution_concurrency: cli.execution_concurrency,
            sqlite_wal: match cli.sqlite_wal {
                true => JournalMode::WAL,
                false => JournalMode::Rollback,
            },
            max_rpc_connections: cli.max_rpc_connections,
            poll_interval: Duration::from_secs(cli.poll_interval.get()),
            l1_poll_interval: Duration::from_secs(cli.l1_poll_interval.get()),
            color: cli.color,
            p2p: P2PConfig::parse_or_exit(cli.p2p),
            debug: DebugConfig::parse(cli.debug),
            verify_tree_hashes: cli.verify_tree_node_data,
            rpc_batch_concurrency_limit: cli.rpc_batch_concurrency_limit,
            is_sync_enabled: cli.is_sync_enabled,
            is_rpc_enabled: cli.is_rpc_enabled,
            gateway_api_key: cli.gateway_api_key,
            event_bloom_filter_cache_size: cli.event_bloom_filter_cache_size,
            get_events_max_blocks_to_scan: cli.get_events_max_blocks_to_scan,
            get_events_max_uncached_bloom_filters_to_load: cli
                .get_events_max_uncached_bloom_filters_to_load,
            gateway_timeout: Duration::from_secs(cli.gateway_timeout.get()),
            feeder_gateway_fetch_concurrency: cli.feeder_gateway_fetch_concurrency,
            state_tries: cli.state_tries,
            custom_versioned_constants: cli
                .custom_versioned_constants_path
                .map(parse_versioned_constants_or_exit),
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
                     subscription sporadically closed due to lagging streams, consider increasing \
                     this buffer. See also `rpc.websocket.topic-capacity`",
        value_name = "CAPACITY",
        default_value = "100",
        env = "PATHFINDER_WEBSOCKET_BUFFER_CAPACITY"
    )]
    pub socket_buffer_capacity: NonZeroUsize,
    #[arg(
        long = "rpc.websocket.topic-capacity",
        long_help = "The topic sender capacity. The topic senders are upstream of socket buffers \
                     and common to all clients and subscriptions. If a variety of clients \
                     regularly have their subscription closed due to a lagging stream, consider \
                     increasing this buffer. See also `rpc.websocket.buffer-capacity`",
        value_name = "CAPACITY",
        default_value = "100",
        env = "PATHFINDER_WEBSOCKET_TOPIC_CAPACITY"
    )]
    pub topic_sender_capacity: NonZeroUsize,
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::{AllowedOrigins, RpcCorsDomainsParseError};
    use crate::config::{parse_cors, ParseVersionedConstantsError};

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

    #[test]
    fn parse_versioned_constants_fails_if_file_not_found() {
        assert_matches!(
            super::parse_versioned_constants("./nonexistent_versioned_constants.json".into()).unwrap_err(),
            ParseVersionedConstantsError::Io(err) => assert_eq!(err.kind(), std::io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn parse_versioned_constants_fails_on_parse_error() {
        assert_matches!(
            super::parse_versioned_constants("resources/invalid_versioned_constants.json".into())
                .unwrap_err(),
            ParseVersionedConstantsError::Parse(_)
        )
    }

    #[test]
    fn parse_versioned_constants_success() {
        super::parse_versioned_constants(
            "../executor/resources/versioned_constants_13_1_1.json".into(),
        )
        .unwrap();
    }
}
