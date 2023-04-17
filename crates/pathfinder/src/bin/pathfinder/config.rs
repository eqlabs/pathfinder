use clap::{CommandFactory, Parser};
use pathfinder_storage::JournalMode;
use reqwest::Url;
use std::net::SocketAddr;
use std::path::PathBuf;

use pathfinder_common::consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT;

#[derive(Parser)]
#[command(name = "Pathfinder")]
#[command(author = "Equilibrium Labs")]
#[command(version = VERGEN_GIT_SEMVER_LIGHTWEIGHT)]
#[command(
    about = "A StarkNet node implemented by Equilibrium Labs. Submit bug reports and issues at https://github.com/eqlabs/pathfinder."
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
        long = "monitor-address",
        long_help = "The address at which pathfinder will serve monitoring related information",
        value_name = "IP:PORT",
        env = "PATHFINDER_MONITOR_ADDRESS"
    )]
    monitor_address: Option<SocketAddr>,

    #[clap(flatten)]
    network: NetworkCli,

    #[arg(
        long = "poll-pending",
        long_help = "Enable polling pending block",
        action = clap::ArgAction::Set,
        default_value = "false",
        env = "PATHFINDER_POLL_PENDING", 
    )]
    poll_pending: bool,

    #[arg(
        long = "python-subprocesses",
        long_help = "Number of Python starknet VMs subprocesses to start",
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
    max_rpc_connections: std::num::NonZeroU32,
}

#[derive(clap::Args)]
struct NetworkCli {
    #[arg(
        long = "network",
        long_help = r"Specify the StarkNet network for pathfinder to operate on.

Note that 'custom' requires also setting the --gateway-url and --feeder-gateway-url options.",
        value_enum,
        env = "PATHFINDER_NETWORK"
    )]
    network: Option<Network>,

    #[arg(
        long,
        long_help = "Set a custom StarkNet chain ID (e.g. SN_GOERLI)",
        value_name = "CHAIN ID",
        env = "PATHFINDER_CHAIN_ID",
        required_if_eq("network", Network::Custom)
    )]
    chain_id: Option<String>,
    #[arg(
        long = "feeder-gateway-url",
        value_name = "URL",
        value_hint = clap::ValueHint::Url,
        long_help = "Specify a custom StarkNet feeder gateway url. Can be used to run pathfinder on a custom StarkNet network, or to use a gateway proxy. Requires '--network custom'.",
        env = "PATHFINDER_FEEDER_GATEWAY_URL", 
        required_if_eq("network", Network::Custom),
    )]
    feeder_gateway: Option<Url>,

    #[arg(
        long = "gateway-url",
        value_name = "URL",
        value_hint = clap::ValueHint::Url,
        long_help = "Specify a custom StarkNet gateway url. Can be used to run pathfinder on a custom StarkNet network, or to use a gateway proxy. Requires '--network custom'.",
        env = "PATHFINDER_GATEWAY_URL",
        required_if_eq("network", Network::Custom),
    )]
    gateway: Option<Url>,
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

pub struct Config {
    pub data_directory: PathBuf,
    pub ethereum: Ethereum,
    pub rpc_address: SocketAddr,
    pub monitor_address: Option<SocketAddr>,
    pub network: Option<NetworkConfig>,
    pub poll_pending: bool,
    pub python_subprocesses: std::num::NonZeroUsize,
    pub sqlite_wal: JournalMode,
    pub max_rpc_connections: std::num::NonZeroU32,
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
            monitor_address: cli.monitor_address,
            network,
            poll_pending: cli.poll_pending,
            python_subprocesses: cli.python_subprocesses,
            sqlite_wal: match cli.sqlite_wal {
                true => JournalMode::WAL,
                false => JournalMode::Rollback,
            },
            max_rpc_connections: cli.max_rpc_connections,
        }
    }
}
