#![deny(rust_2018_idioms)]

use anyhow::Context;
use metrics_exporter_prometheus::PrometheusBuilder;
use pathfinder_common::EthereumAddress;
use pathfinder_common::{consts::VERGEN_GIT_DESCRIBE, BlockNumber, Chain, ChainId, EthereumChain};
use pathfinder_ethereum::{EthereumApi, EthereumClient};
use pathfinder_lib::{
    monitoring::{self},
    state,
};
use pathfinder_rpc::{cairo, metrics::logger::RpcMetricsLogger, SyncState};
use pathfinder_storage::Storage;
use starknet_gateway_client::GatewayApi;
use starknet_gateway_types::pending::PendingData;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{atomic::AtomicBool, Arc};
use tracing::info;

use crate::config::NetworkConfig;

mod config;
mod update;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        // Disable all dependency logs by default.
        std::env::set_var("RUST_LOG", "pathfinder=info");
    }

    setup_tracing();

    let config = config::Config::parse();

    info!(
        // this is expected to be $(last_git_tag)-$(commits_since)-$(commit_hash)
        version = VERGEN_GIT_DESCRIBE,
        "🏁 Starting node."
    );

    permission_check(&config.data_directory)?;

    // A readiness flag which is used to indicate that pathfinder is ready via monitoring.
    let readiness = Arc::new(AtomicBool::new(false));

    // Spawn monitoring if configured.
    if let Some(address) = config.monitor_address {
        spawn_monitoring(address, readiness.clone())
            .await
            .context("Starting monitoring task")?;
    }

    let ethereum = EthereumContext::setup(config.ethereum.url, config.ethereum.password)
        .await
        .context("Creating Ethereum context")?;

    // Use the default starknet network if none was configured.
    let network = match config.network {
        Some(network) => network,
        None => ethereum
            .default_network()
            .context("Using default Starknet network based on Ethereum configuration")?,
    };

    let pathfinder_context =
        PathfinderContext::configure_and_proxy_check(network, config.data_directory)
            .await
            .context("Configuring pathfinder")?;

    verify_networks(pathfinder_context.network, ethereum.chain)?;

    // Setup and verify database
    let storage = Storage::migrate(pathfinder_context.database.clone(), config.sqlite_wal).unwrap();
    info!(location=?pathfinder_context.database, "Database migrated.");
    verify_database(
        &storage,
        pathfinder_context.network,
        &pathfinder_context.gateway,
    )
    .await
    .context("Verifying database")?;

    let sync_state = Arc::new(SyncState::default());
    let pending_state = PendingData::default();
    let pending_interval = match config.poll_pending {
        true => Some(std::time::Duration::from_secs(5)),
        false => None,
    };

    let (call_handle, cairo_handle) = cairo::ext_py::start(
        storage.path().into(),
        config.python_subprocesses,
        futures::future::pending(),
        pathfinder_context.network,
    )
    .await
    .context(
        "Creating python process for call handling. Have you setup our Python dependencies?",
    )?;

    let shared = pathfinder_rpc::gas_price::Cached::new(pathfinder_context.gateway.clone());

    let context = pathfinder_rpc::context::RpcContext::new(
        storage.clone(),
        sync_state.clone(),
        pathfinder_context.network_id,
        pathfinder_context.gateway.clone(),
    )
    .with_call_handling(call_handle)
    .with_eth_gas_price(shared);
    let context = match config.poll_pending {
        true => context.with_pending_data(pending_state.clone()),
        false => context,
    };

    let rpc_server = pathfinder_rpc::RpcServer::new(config.rpc_address, context);
    let rpc_server = match config.rpc_cors_domains {
        Some(allowed_origins) => rpc_server.with_cors(allowed_origins),
        None => rpc_server,
    };

    let rpc_server = match config.ws {
        Some(ws) => rpc_server.with_ws(ws.capacity),
        None => rpc_server,
    };

    let sync_handle = tokio::spawn(state::sync(
        storage.clone(),
        ethereum.client,
        pathfinder_context.network,
        pathfinder_context.network_id,
        pathfinder_context.l1_core_address.0,
        pathfinder_context.gateway,
        sync_state.clone(),
        state::l1::sync,
        state::l2::sync,
        pending_state,
        pending_interval,
        state::l2::BlockValidationMode::Strict,
        rpc_server.get_ws_senders(),
        1_000,
    ));

    let (rpc_handle, local_addr) = rpc_server
        .with_logger(RpcMetricsLogger)
        .with_max_connections(config.max_rpc_connections.get())
        .run()
        .await
        .context("Starting the RPC server")?;

    info!("📡 HTTP-RPC server started on: {}", local_addr);

    let p2p_handle = start_p2p(pathfinder_context.network_id, storage, sync_state).await?;

    let update_handle = tokio::spawn(update::poll_github_for_releases());

    // We are now ready.
    readiness.store(true, std::sync::atomic::Ordering::Relaxed);

    // Monitor our spawned process tasks.
    tokio::select! {
        result = sync_handle => {
            match result {
                Ok(task_result) => tracing::error!("Sync process ended unexpected with: {:?}", task_result),
                Err(err) => tracing::error!("Sync process ended unexpected; failed to join task handle: {:?}", err),
            }
        }
        result = cairo_handle => {
            match result {
                Ok(task_result) => tracing::error!("Cairo process ended unexpected with: {:?}", task_result),
                Err(err) => tracing::error!("Cairo process ended unexpected; failed to join task handle: {:?}", err),
            }
        }
        _result = rpc_handle.stopped() => {
            // This handle returns () so its not very useful.
            tracing::error!("RPC server process ended unexpected");
        }
        result = update_handle => {
            match result {
                Ok(_) => tracing::error!("Release monitoring process ended unexpectedly"),
                Err(err) => tracing::error!(error=%err, "Release monitoring process ended unexpectedly"),
            }
        }
        result = p2p_handle => {
            match result {
                Ok(_) => tracing::error!("P2P process ended unexpectedly"),
                Err(err) => tracing::error!(error=%err, "P2P process ended unexpectedly"),
            }
        }
    }

    Ok(())
}

#[cfg(feature = "tokio-console")]
fn setup_tracing() {
    use tracing_subscriber::prelude::*;

    // EnvFilter isn't really a Filter, so this we need this ugly workaround for filtering with it.
    // See https://github.com/tokio-rs/tracing/issues/1868 for more details.
    let env_filter = Arc::new(tracing_subscriber::EnvFilter::from_default_env());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_target(false)
        .compact()
        .with_filter(tracing_subscriber::filter::dynamic_filter_fn(
            move |m, c| env_filter.enabled(m, c.clone()),
        ));
    let console_layer = console_subscriber::spawn();
    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(console_layer)
        .init();
}

#[cfg(not(feature = "tokio-console"))]
fn setup_tracing() {
    use time::macros::format_description;

    let time_fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let time_fmt = tracing_subscriber::fmt::time::UtcTime::new(time_fmt);

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .with_timer(time_fmt)
        .compact()
        .init();
}

fn permission_check(base: &std::path::Path) -> Result<(), anyhow::Error> {
    tempfile::tempfile_in(base)
        .with_context(|| format!("Failed to create a file in {}. Make sure the directory is writable by the user running pathfinder.", base.display()))?;

    // well, don't really know what else to check

    Ok(())
}

#[cfg(feature = "p2p")]
async fn start_p2p(
    chain_id: ChainId,
    storage: Storage,
    sync_state: Arc<SyncState>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let p2p_listen_address = std::env::var("PATHFINDER_P2P_LISTEN_ADDRESS")
        .unwrap_or_else(|_| "/ip4/0.0.0.0/tcp/4001".to_owned());
    let listen_on: p2p::libp2p::Multiaddr = p2p_listen_address.parse()?;

    let p2p_bootstrap_addresses = std::env::var("PATHFINDER_P2P_BOOTSTRAP_MULTIADDRESSES")?;
    let bootstrap_addresses = p2p_bootstrap_addresses
        .split_ascii_whitespace()
        .map(|a| a.parse::<p2p::libp2p::Multiaddr>())
        .collect::<Result<Vec<_>, _>>()?;

    let (_p2p_peers, _p2p_client, p2p_handle) = pathfinder_lib::p2p_network::start(
        chain_id,
        storage,
        sync_state,
        listen_on,
        &bootstrap_addresses,
    )
    .await?;

    Ok(p2p_handle)
}

#[cfg(not(feature = "p2p"))]
async fn start_p2p(
    _chain_id: ChainId,
    _storage: Storage,
    _sync_state: Arc<SyncState>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let join_handle = tokio::task::spawn(async move { futures::future::pending().await });

    Ok(join_handle)
}

/// Spawns the monitoring task at the given address.
async fn spawn_monitoring(
    address: SocketAddr,
    readiness: Arc<AtomicBool>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let prometheus_handle = PrometheusBuilder::new()
        .install_recorder()
        .context("Creating Prometheus recorder")?;

    let handle = monitoring::spawn_server(address, readiness, prometheus_handle).await;
    Ok(handle)
}

/// Convenience bundle for an Ethereum transport and chain.
struct EthereumContext {
    client: EthereumClient,
    chain: EthereumChain,
}

impl EthereumContext {
    /// Configure an [EthereumContext]'s transport and read the chain ID using it.
    async fn setup(url: reqwest::Url, password: Option<String>) -> anyhow::Result<Self> {
        let client = EthereumClient::from_config(url, password).context("Creating transport")?;

        let chain = client.get_chain().await.context(
            r"Determining Ethereum chain.
                            
Hint: Make sure the provided ethereum.url and ethereum.password are good.",
        )?;

        Ok(Self { client, chain })
    }

    /// Maps the Ethereum network to its default Starknet network:
    ///     Mainnet => Mainnet
    ///     Goerli  => Testnet
    fn default_network(&self) -> anyhow::Result<NetworkConfig> {
        match self.chain {
            EthereumChain::Mainnet => Ok(NetworkConfig::Mainnet),
            EthereumChain::Goerli => Ok(NetworkConfig::Testnet),
            EthereumChain::Other(id) => {
                anyhow::bail!(
                    r"Implicit Starknet networks are only available for Ethereum mainnet and Goerli, but the provided Ethereum network has chain ID = {id}.

If you are trying to connect to a custom Starknet on another Ethereum network, please use '--network custom'"
                )
            }
        }
    }
}

struct PathfinderContext {
    network: Chain,
    network_id: ChainId,
    gateway: starknet_gateway_client::Client,
    database: PathBuf,
    l1_core_address: EthereumAddress,
}

/// Used to hide private fn's for [PathfinderContext].
mod pathfinder_context {
    use super::PathfinderContext;
    use crate::config::NetworkConfig;

    use std::path::PathBuf;

    use anyhow::Context;
    use pathfinder_common::{Chain, ChainId, EthereumAddress};
    use pathfinder_ethereum::core_addr;
    use primitive_types::H160;
    use reqwest::Url;
    use starknet_gateway_client::Client as GatewayClient;

    impl PathfinderContext {
        pub async fn configure_and_proxy_check(
            cfg: NetworkConfig,
            data_directory: PathBuf,
        ) -> anyhow::Result<Self> {
            let context = match cfg {
                NetworkConfig::Mainnet => Self {
                    network: Chain::Mainnet,
                    network_id: ChainId::MAINNET,
                    gateway: GatewayClient::mainnet(),
                    database: data_directory.join("mainnet.sqlite"),
                    l1_core_address: EthereumAddress(H160::from(core_addr::MAINNET)),
                },
                NetworkConfig::Testnet => Self {
                    network: Chain::Testnet,
                    network_id: ChainId::TESTNET,
                    gateway: GatewayClient::testnet(),
                    database: data_directory.join("goerli.sqlite"),
                    l1_core_address: EthereumAddress(H160::from(core_addr::TESTNET)),
                },
                NetworkConfig::Testnet2 => Self {
                    network: Chain::Testnet2,
                    network_id: ChainId::TESTNET2,
                    gateway: GatewayClient::testnet2(),
                    database: data_directory.join("testnet2.sqlite"),
                    l1_core_address: EthereumAddress(H160::from(core_addr::TESTNET2)),
                },
                NetworkConfig::Integration => Self {
                    network: Chain::Integration,
                    network_id: ChainId::INTEGRATION,
                    gateway: GatewayClient::integration(),
                    database: data_directory.join("integration.sqlite"),
                    l1_core_address: EthereumAddress(H160::from(core_addr::INTEGRATION)),
                },
                NetworkConfig::Custom {
                    gateway,
                    feeder_gateway,
                    chain_id,
                } => Self::configure_custom(gateway, feeder_gateway, chain_id, data_directory)
                    .await
                    .context("Configuring custom network")?,
            };

            Ok(context)
        }

        /// Creates a [PathfinderContext] for a custom network. Provides additional verification
        /// by checking for a proxy gateway by comparing against L1 starknet address against of
        /// the known networks.
        async fn configure_custom(
            gateway: Url,
            feeder: Url,
            chain_id: String,
            data_directory: PathBuf,
        ) -> anyhow::Result<Self> {
            use stark_hash::Felt;
            use starknet_gateway_client::GatewayApi;

            let gateway =
                GatewayClient::with_urls(gateway, feeder).context("Creating gateway client")?;

            let network_id =
                ChainId(Felt::from_be_slice(chain_id.as_bytes()).context("Parsing chain ID")?);

            let l1_core_address = gateway
                .eth_contract_addresses()
                .await
                .context("Downloading starknet L1 address from gateway for proxy check")?
                .starknet;

            // Check for proxies by comparing the core address against those of the known networks.
            let network = match l1_core_address.0.as_bytes() {
                x if x == core_addr::MAINNET => Chain::Mainnet,
                x if x == core_addr::TESTNET => Chain::Testnet,
                x if x == core_addr::TESTNET2 => Chain::Testnet2,
                x if x == core_addr::INTEGRATION => Chain::Integration,
                _ => Chain::Custom,
            };

            if network != Chain::Custom {
                tracing::info!(%network, "Proxy gateway detected");
            }

            let context = Self {
                network,
                network_id,
                gateway,
                database: data_directory.join("custom.sqlite"),
                l1_core_address,
            };

            Ok(context)
        }
    }
}

/// Errors if there is a mismatch between the starknet and ethereum networks.
fn verify_networks(starknet: Chain, ethereum: EthereumChain) -> anyhow::Result<()> {
    if starknet != Chain::Custom {
        let expected = match starknet {
            Chain::Mainnet => EthereumChain::Mainnet,
            Chain::Testnet => EthereumChain::Goerli,
            Chain::Integration => EthereumChain::Goerli,
            Chain::Testnet2 => EthereumChain::Goerli,
            Chain::Custom => unreachable!("Already checked against"),
        };

        anyhow::ensure!(ethereum == expected, "Incorrect Ethereum network detected. Found {ethereum:?} but expected {expected:?} for {} Starknet", starknet);
    }

    Ok(())
}

async fn verify_database(
    storage: &Storage,
    network: Chain,
    gateway_client: &starknet_gateway_client::Client,
) -> anyhow::Result<()> {
    use pathfinder_storage::StarknetBlocksTable;

    let storage = storage.clone();
    let db_genesis = tokio::task::spawn_blocking(move || {
        let mut conn = storage.connection().context("Create database connection")?;
        let tx = conn.transaction().context("Create database transaction")?;

        StarknetBlocksTable::get_hash(&tx, BlockNumber::GENESIS.into())
    })
    .await
    .context("Fetching genesis hash from database")?
    .context("Waiting for genesis block to be fetched from database")?;

    if let Some(database_genesis) = db_genesis {
        use pathfinder_common::consts::{
            INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH,
            TESTNET_GENESIS_HASH,
        };

        let db_network = match database_genesis {
            MAINNET_GENESIS_HASH => Chain::Mainnet,
            TESTNET_GENESIS_HASH => Chain::Testnet,
            TESTNET2_GENESIS_HASH => Chain::Testnet2,
            INTEGRATION_GENESIS_HASH => Chain::Integration,
            _other => Chain::Custom,
        };

        match (network, db_network) {
            (Chain::Custom, _) => {
                // Verify against gateway.
                let gateway_block = gateway_client
                    .block(BlockNumber::GENESIS.into())
                    .await
                    .context("Downloading genesis block from gateway for database verification")?
                    .as_block()
                    .context("Genesis block should not be pending")?;

                anyhow::ensure!(
                    database_genesis == gateway_block.block_hash,
                    "Database genesis block does not match gateway. {} != {}",
                    database_genesis,
                    gateway_block.block_hash
                );
            }
            (network, db_network) => anyhow::ensure!(
                network == db_network,
                "Database ({}) does not match the expected network ({})",
                db_network,
                network
            ),
        }
    }

    Ok(())
}
