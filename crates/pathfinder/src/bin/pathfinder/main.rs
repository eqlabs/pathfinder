#![deny(rust_2018_idioms)]

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Context;
use metrics_exporter_prometheus::PrometheusBuilder;
use pathfinder_common::consts::VERGEN_GIT_DESCRIBE;
use pathfinder_common::{BlockNumber, Chain, ChainId, EthereumChain};
use pathfinder_ethereum::{EthereumApi, EthereumClient};
use pathfinder_lib::monitoring::{self};
use pathfinder_lib::state;
use pathfinder_lib::state::SyncContext;
use pathfinder_rpc::context::WebsocketContext;
use pathfinder_rpc::SyncState;
use pathfinder_storage::Storage;
use primitive_types::H160;
use starknet_gateway_client::GatewayApi;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

use crate::config::{NetworkConfig, StateTries};

mod config;
mod update;

// The Cairo VM allocates felts on the stack, so during execution it's making
// a huge number of allocations. We get roughly two times better execution
// performance by using jemalloc (compared to the Linux glibc allocator).
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .unwrap()
        .block_on(async { async_main().await })
}

async fn async_main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        // Disable all dependency logs by default.
        std::env::set_var("RUST_LOG", "pathfinder=info");
    }

    let mut config = config::Config::parse();

    setup_tracing(config.color, config.debug.pretty_log);

    info!(
        // this is expected to be $(last_git_tag)-$(commits_since)-$(commit_hash)
        version = VERGEN_GIT_DESCRIBE,
        "🏁 Starting node."
    );

    if !config.data_directory.exists() {
        std::fs::DirBuilder::new()
            .create(&config.data_directory)
            .context("Creating database directory")?;
    }

    permission_check(&config.data_directory)?;

    let available_parallelism = std::thread::available_parallelism()?;

    rayon::ThreadPoolBuilder::new()
        .thread_name(|thread_index| format!("rayon-{}", thread_index))
        .num_threads(available_parallelism.get())
        .build_global()?;

    // A readiness flag which is used to indicate that pathfinder is ready via
    // monitoring.
    let readiness = Arc::new(AtomicBool::new(false));

    let sync_state = Arc::new(SyncState::default());

    let ethereum = EthereumContext::setup(config.ethereum.url.clone(), &config.ethereum.password)
        .await
        .context("Creating Ethereum context")?;

    // Use the default starknet network if none was configured.
    let network = match config.network {
        Some(ref network) => network.clone(),
        None => ethereum
            .default_network()
            .context("Using default Starknet network based on Ethereum configuration")?,
    };

    // Spawn monitoring if configured.
    if let Some(address) = config.monitor_address {
        let network_label = match &network {
            NetworkConfig::Mainnet => "mainnet",
            NetworkConfig::SepoliaTestnet => "testnet-sepolia",
            NetworkConfig::SepoliaIntegration => "integration-sepolia",
            NetworkConfig::Custom { .. } => "custom",
        };
        spawn_monitoring(
            network_label,
            address,
            readiness.clone(),
            sync_state.clone(),
        )
        .await
        .context("Starting monitoring task")?;
    }

    let pathfinder_context = PathfinderContext::configure_and_proxy_check(
        network,
        &config.data_directory,
        config.gateway_api_key.clone(),
        config.gateway_timeout,
    )
    .await
    .context("Configuring pathfinder")?;

    verify_networks(pathfinder_context.network, ethereum.chain)?;

    let gateway_public_key = pathfinder_context
        .gateway
        .public_key()
        .await
        .context("Fetching Starknet gateway public key")?;

    // Setup and verify database

    let storage_manager =
        pathfinder_storage::StorageBuilder::file(pathfinder_context.database.clone())
            .journal_mode(config.sqlite_wal)
            .bloom_filter_cache_size(config.event_bloom_filter_cache_size.get())
            .trie_prune_mode(match config.state_tries {
                Some(StateTries::Pruned(num_blocks_kept)) => {
                    Some(pathfinder_storage::TriePruneMode::Prune { num_blocks_kept })
                }
                Some(StateTries::Archive) => Some(pathfinder_storage::TriePruneMode::Archive),
                None => None,
            })
            .migrate()?;
    let sync_storage = storage_manager
        // 5 is enough for normal sync operations, and then `available_parallelism` for
        // the rayon thread pool workers to use.
        .create_pool(NonZeroU32::new(5 + available_parallelism.get() as u32).unwrap())
        .context(
            r"Creating database connection pool for sync.

Hint: This is usually caused by exceeding the file descriptor limit of your system.
      Try increasing the file limit to using `ulimit` or similar tooling.",
        )?;

    // Set the rpc file connection limit to a fraction of the RPC connections.
    // Having this be too large is counter productive as disk IO will then slow down
    // all queries.
    let max_rpc_connections: u32 = config
        .max_rpc_connections
        .get()
        .try_into()
        .expect("usize should cast to u32");
    let rpc_storage = std::cmp::max(10, max_rpc_connections / 8);
    let rpc_storage = NonZeroU32::new(rpc_storage).expect("A non-zero minimum is set");
    let rpc_storage = storage_manager.create_read_only_pool(rpc_storage).context(
        r"Creating database connection pool for RPC

Hint: This is usually caused by exceeding the file descriptor limit of your system.
      Try increasing the file limit to using `ulimit` or similar tooling.",
    )?;

    let execution_storage_pool_size = config.execution_concurrency.unwrap_or_else(|| {
        std::num::NonZeroU32::new(available_parallelism.get() as u32)
            .expect("The number of CPU cores should be non-zero")
    });
    let execution_storage = storage_manager
        .create_read_only_pool(execution_storage_pool_size)
        .context(
            r"Creating database connection pool for execution

Hint: This is usually caused by exceeding the file descriptor limit of your system.
      Try increasing the file limit to using `ulimit` or similar tooling.",
        )?;

    let p2p_storage = storage_manager
        .create_pool(NonZeroU32::new(1).unwrap())
        .context(
            r"Creating database connection pool for p2p

Hint: This is usually caused by exceeding the file descriptor limit of your system.
      Try increasing the file limit to using `ulimit` or similar tooling.",
        )?;

    info!(location=?pathfinder_context.database, "Database migrated.");
    verify_database(
        &sync_storage,
        pathfinder_context.network,
        &pathfinder_context.gateway,
    )
    .await
    .context("Verifying database")?;

    sync_storage
        .connection()
        .context("Creating database connection")?
        .transaction()
        .context(r"Creating database transaction")?
        .prune_tries()
        .context("Pruning tries on startup")?;

    let (tx_pending, rx_pending) = tokio::sync::watch::channel(Default::default());

    let rpc_config = pathfinder_rpc::context::RpcConfig {
        batch_concurrency_limit: config.rpc_batch_concurrency_limit,
        get_events_max_blocks_to_scan: config.get_events_max_blocks_to_scan,
        get_events_max_uncached_bloom_filters_to_load: config
            .get_events_max_uncached_bloom_filters_to_load,
        custom_versioned_constants: config.custom_versioned_constants.take(),
    };

    let context = pathfinder_rpc::context::RpcContext::new(
        rpc_storage,
        execution_storage,
        sync_state.clone(),
        pathfinder_context.network_id,
        pathfinder_context.gateway.clone(),
        rx_pending.clone(),
        rpc_config,
    );

    let context = if config.websocket.enabled {
        context.with_websockets(WebsocketContext::new(
            config.websocket.socket_buffer_capacity,
            config.websocket.topic_sender_capacity,
            rx_pending,
        ))
    } else {
        context
    };

    let default_version = match config.rpc_root_version {
        config::RpcVersion::V06 => pathfinder_rpc::RpcVersion::V06,
        config::RpcVersion::V07 => pathfinder_rpc::RpcVersion::V07,
    };

    let rpc_server = pathfinder_rpc::RpcServer::new(config.rpc_address, context, default_version);
    let rpc_server = match config.rpc_cors_domains {
        Some(ref allowed_origins) => rpc_server.with_cors(allowed_origins.clone()),
        None => rpc_server,
    };

    let (p2p_handle, gossiper, p2p_client) = start_p2p(
        pathfinder_context.network_id,
        p2p_storage,
        config.p2p.clone(),
    )
    .await?;

    let sync_handle = if config.is_sync_enabled {
        start_sync(
            sync_storage,
            pathfinder_context,
            ethereum.client,
            sync_state.clone(),
            &config,
            tx_pending,
            rpc_server.get_topic_broadcasters().cloned(),
            gossiper,
            gateway_public_key,
            p2p_client,
            config.verify_tree_hashes,
        )
    } else {
        tokio::task::spawn(futures::future::pending())
    };

    let rpc_handle = if config.is_rpc_enabled {
        let (rpc_handle, local_addr) = rpc_server
            .with_max_connections(config.max_rpc_connections.get())
            .spawn()
            .await
            .context("Starting the RPC server")?;
        info!("📡 HTTP-RPC server started on: {}", local_addr);
        rpc_handle
    } else {
        tokio::spawn(std::future::pending())
    };

    tokio::spawn(update::poll_github_for_releases());

    let mut term_signal = signal(SignalKind::terminate())?;
    let mut int_signal = signal(SignalKind::interrupt())?;

    // We are now ready.
    readiness.store(true, std::sync::atomic::Ordering::Relaxed);

    // Monitor our critical spawned process tasks.
    tokio::select! {
        result = sync_handle => {
            match result {
                Ok(task_result) => tracing::error!("Sync process ended unexpected with: {:?}", task_result),
                Err(err) => tracing::error!("Sync process ended unexpected; failed to join task handle: {:?}", err),
            }
            anyhow::bail!("Unexpected shutdown");
        }
        result = rpc_handle => {
            match result {
                Ok(_) => tracing::error!("RPC server process ended unexpectedly"),
                Err(err) => tracing::error!(error=%err, "RPC server process ended unexpectedly"),
            }
            anyhow::bail!("Unexpected shutdown");
        }
        result = p2p_handle => {
            match result {
                Ok(_) => tracing::error!("P2P process ended unexpectedly"),
                Err(err) => tracing::error!(error=%err, "P2P process ended unexpectedly"),
            }
            anyhow::bail!("Unexpected shutdown");
        }
        _ = term_signal.recv() => {
            tracing::info!("TERM signal received, exiting gracefully");
            Ok(())
        }
        _ = int_signal.recv() => {
            tracing::info!("INT signal received, exiting gracefully");
            Ok(())
        }
    }
}

#[cfg(feature = "tokio-console")]
fn setup_tracing(color: config::Color, pretty_log: bool) {
    use tracing_subscriber::prelude::*;

    // EnvFilter isn't really a Filter, so this we need this ugly workaround for
    // filtering with it. See https://github.com/tokio-rs/tracing/issues/1868 for more details.
    let env_filter = Arc::new(tracing_subscriber::EnvFilter::from_default_env());
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(color.is_color_enabled())
        .with_target(pretty_log);
    let filter =
        tracing_subscriber::filter::dynamic_filter_fn(move |m, c| env_filter.enabled(m, c.clone()));

    if pretty_log {
        tracing_subscriber::registry()
            .with(fmt_layer.pretty().with_filter(filter))
            .with(console_subscriber::spawn())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt_layer.compact().with_filter(filter))
            .with(console_subscriber::spawn())
            .init();
    }
}

#[cfg(not(feature = "tokio-console"))]
fn setup_tracing(color: config::Color, pretty_log: bool) {
    use time::macros::format_description;

    let time_fmt = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]");
    let time_fmt = tracing_subscriber::fmt::time::UtcTime::new(time_fmt);

    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(pretty_log)
        .with_timer(time_fmt)
        .with_ansi(color.is_color_enabled());

    if pretty_log {
        subscriber.pretty().init();
    } else {
        subscriber.compact().init();
    }
}

fn permission_check(base: &std::path::Path) -> Result<(), anyhow::Error> {
    tempfile::tempfile_in(base).with_context(|| {
        format!(
            "Failed to create a file in {}. Make sure the directory is writable by the user \
             running pathfinder.",
            base.display()
        )
    })?;

    // well, don't really know what else to check

    Ok(())
}

#[cfg(feature = "p2p")]
async fn start_p2p(
    chain_id: ChainId,
    storage: Storage,
    config: config::P2PConfig,
) -> anyhow::Result<(
    tokio::task::JoinHandle<()>,
    state::Gossiper,
    Option<p2p::client::peer_agnostic::Client>,
)> {
    use std::path::Path;
    use std::time::Duration;

    use p2p::libp2p::identity::Keypair;
    use pathfinder_lib::p2p_network::P2PContext;
    use serde::Deserialize;
    use zeroize::Zeroizing;

    #[derive(Clone, Deserialize)]
    struct IdentityConfig {
        pub private_key: String,
    }

    impl IdentityConfig {
        pub fn from_file(path: &Path) -> anyhow::Result<Self> {
            Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
        }
    }

    impl zeroize::Zeroize for IdentityConfig {
        fn zeroize(&mut self) {
            self.private_key.zeroize()
        }
    }

    let keypair = match config.identity_config_file {
        Some(path) => {
            let config = Zeroizing::new(IdentityConfig::from_file(path.as_path())?);
            let private_key = Zeroizing::new(base64::decode(config.private_key.as_bytes())?);
            Keypair::from_protobuf_encoding(&private_key)?
        }
        None => {
            tracing::info!("No private key configured, generating a new one");
            Keypair::generate_ed25519()
        }
    };

    let context = P2PContext {
        cfg: p2p::Config {
            direct_connection_timeout: config.direct_connection_timeout,
            relay_connection_timeout: Duration::from_secs(10),
            max_inbound_direct_peers: config.max_inbound_direct_connections,
            max_inbound_relayed_peers: config.max_inbound_relayed_connections,
            max_outbound_peers: config.max_outbound_connections,
            low_watermark: config.low_watermark,
            ip_whitelist: config.ip_whitelist,
            bootstrap: Default::default(),
            eviction_timeout: config.eviction_timeout,
            inbound_connections_rate_limit: p2p::RateLimit {
                max: 10,
                interval: Duration::from_secs(1),
            },
            kad_names: config.kad_names,
            stream_timeout: config.stream_timeout,
            max_concurrent_streams: config.max_concurrent_streams,
        },
        chain_id,
        storage,
        proxy: config.proxy,
        keypair,
        listen_on: config.listen_on,
        bootstrap_addresses: config.bootstrap_addresses,
        predefined_peers: config.predefined_peers,
    };

    let (p2p_client, _head_receiver, p2p_handle) =
        pathfinder_lib::p2p_network::start(context).await?;

    Ok((
        p2p_handle,
        state::Gossiper::new(p2p_client.clone()),
        Some(p2p_client),
    ))
}

#[cfg(not(feature = "p2p"))]
async fn start_p2p(
    _: ChainId,
    _: Storage,
    _: config::P2PConfig,
) -> anyhow::Result<(
    tokio::task::JoinHandle<()>,
    state::Gossiper,
    Option<p2p::client::peer_agnostic::Client>,
)> {
    let join_handle = tokio::task::spawn(futures::future::pending());

    Ok((join_handle, Default::default(), None))
}

#[cfg(feature = "p2p")]
#[allow(clippy::too_many_arguments)]
fn start_sync(
    storage: Storage,
    pathfinder_context: PathfinderContext,
    ethereum_client: EthereumClient,
    sync_state: Arc<SyncState>,
    config: &config::Config,
    tx_pending: tokio::sync::watch::Sender<pathfinder_rpc::PendingData>,
    websocket_txs: Option<pathfinder_rpc::TopicBroadcasters>,
    gossiper: state::Gossiper,
    gateway_public_key: pathfinder_common::PublicKey,
    p2p_client: Option<p2p::client::peer_agnostic::Client>,
    verify_tree_hashes: bool,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    if config.p2p.proxy {
        start_feeder_gateway_sync(
            storage,
            pathfinder_context,
            ethereum_client,
            sync_state,
            config,
            tx_pending,
            websocket_txs,
            gossiper,
            gateway_public_key,
        )
    } else {
        let p2p_client = p2p_client.expect("P2P client is expected with the p2p feature enabled");
        start_p2p_sync(
            storage,
            pathfinder_context,
            ethereum_client,
            p2p_client,
            gateway_public_key,
            config.p2p.l1_checkpoint_override,
            verify_tree_hashes,
        )
    }
}

#[cfg(not(feature = "p2p"))]
#[allow(clippy::too_many_arguments)]
fn start_sync(
    storage: Storage,
    pathfinder_context: PathfinderContext,
    ethereum_client: EthereumClient,
    sync_state: Arc<SyncState>,
    config: &config::Config,
    tx_pending: tokio::sync::watch::Sender<pathfinder_rpc::PendingData>,
    websocket_txs: Option<pathfinder_rpc::TopicBroadcasters>,
    gossiper: state::Gossiper,
    gateway_public_key: pathfinder_common::PublicKey,
    _p2p_client: Option<p2p::client::peer_agnostic::Client>,
    _verify_tree_hashes: bool,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    start_feeder_gateway_sync(
        storage,
        pathfinder_context,
        ethereum_client,
        sync_state,
        config,
        tx_pending,
        websocket_txs,
        gossiper,
        gateway_public_key,
    )
}

#[allow(clippy::too_many_arguments)]
fn start_feeder_gateway_sync(
    storage: Storage,
    pathfinder_context: PathfinderContext,
    ethereum_client: EthereumClient,
    sync_state: Arc<SyncState>,
    config: &config::Config,
    tx_pending: tokio::sync::watch::Sender<pathfinder_rpc::PendingData>,
    websocket_txs: Option<pathfinder_rpc::TopicBroadcasters>,
    gossiper: state::Gossiper,
    gateway_public_key: pathfinder_common::PublicKey,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let sync_context = SyncContext {
        storage,
        ethereum: ethereum_client,
        chain: pathfinder_context.network,
        chain_id: pathfinder_context.network_id,
        core_address: pathfinder_context.l1_core_address,
        sequencer: pathfinder_context.gateway,
        state: sync_state.clone(),
        head_poll_interval: config.poll_interval,
        l1_poll_interval: config.l1_poll_interval,
        pending_data: tx_pending,
        block_validation_mode: state::l2::BlockValidationMode::Strict,
        websocket_txs,
        block_cache_size: 1_000,
        restart_delay: config.debug.restart_delay,
        verify_tree_hashes: config.verify_tree_hashes,
        gossiper,
        sequencer_public_key: gateway_public_key,
        fetch_concurrency: config.feeder_gateway_fetch_concurrency,
    };

    tokio::spawn(state::sync(sync_context, state::l1::sync, state::l2::sync))
}

#[cfg(feature = "p2p")]
fn start_p2p_sync(
    storage: Storage,
    pathfinder_context: PathfinderContext,
    ethereum_client: EthereumClient,
    p2p_client: p2p::client::peer_agnostic::Client,
    gateway_public_key: pathfinder_common::PublicKey,
    l1_checkpoint_override: Option<pathfinder_ethereum::EthereumStateUpdate>,
    verify_tree_hashes: bool,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    let sync = pathfinder_lib::sync::Sync {
        storage,
        p2p: p2p_client,
        eth_client: ethereum_client,
        eth_address: pathfinder_context.l1_core_address,
        fgw_client: pathfinder_context.gateway,
        chain_id: pathfinder_context.network_id,
        chain: pathfinder_context.network,
        public_key: gateway_public_key,
        l1_checkpoint_override,
        verify_tree_hashes,
    };
    tokio::spawn(sync.run())
}

/// Spawns the monitoring task at the given address.
async fn spawn_monitoring(
    network: &str,
    address: SocketAddr,
    readiness: Arc<AtomicBool>,
    sync_state: Arc<SyncState>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let prometheus_handle = PrometheusBuilder::new()
        .add_global_label("network", network)
        .install_recorder()
        .context("Creating Prometheus recorder")?;

    metrics::gauge!("pathfinder_build_info", 1.0, "version" => VERGEN_GIT_DESCRIBE);

    let (_, handle) =
        monitoring::spawn_server(address, readiness, sync_state, prometheus_handle).await?;
    Ok(handle)
}

/// Convenience bundle for an Ethereum transport and chain.
struct EthereumContext {
    client: EthereumClient,
    chain: EthereumChain,
}

impl EthereumContext {
    /// Configure an [EthereumContext]'s transport and read the chain ID using
    /// it.
    async fn setup(url: reqwest::Url, password: &Option<String>) -> anyhow::Result<Self> {
        let client = if let Some(password) = password.as_ref() {
            EthereumClient::with_password(url, password).context("Creating Ethereum client")?
        } else {
            EthereumClient::new(url).context("Creating Ethereum client")?
        };

        let chain = client.get_chain().await.context(
            r"Determining Ethereum chain.
                            
Hint: Make sure the provided ethereum.url and ethereum.password are good.",
        )?;

        Ok(Self { client, chain })
    }

    /// Maps the Ethereum network to its default Starknet network:
    ///     Mainnet => Mainnet
    ///     Sepolia => Testnet/Sepolia
    fn default_network(&self) -> anyhow::Result<NetworkConfig> {
        match self.chain {
            EthereumChain::Mainnet => Ok(NetworkConfig::Mainnet),
            EthereumChain::Sepolia => Ok(NetworkConfig::SepoliaTestnet),
            EthereumChain::Other(id) => {
                anyhow::bail!(
                    r"Implicit Starknet networks are only available for Ethereum mainnet and Sepolia, but the provided Ethereum network has chain ID = {id}.

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
    l1_core_address: H160,
}

/// Used to hide private fn's for [PathfinderContext].
mod pathfinder_context {
    use std::path::Path;
    use std::time::Duration;

    use anyhow::Context;
    use pathfinder_common::{Chain, ChainId};
    use pathfinder_ethereum::core_addr;
    use primitive_types::H160;
    use reqwest::Url;
    use starknet_gateway_client::Client as GatewayClient;

    use super::PathfinderContext;
    use crate::config::NetworkConfig;

    impl PathfinderContext {
        pub async fn configure_and_proxy_check(
            cfg: NetworkConfig,
            data_directory: &Path,
            api_key: Option<String>,
            gateway_timeout: Duration,
        ) -> anyhow::Result<Self> {
            let context = match cfg {
                NetworkConfig::Mainnet => Self {
                    network: Chain::Mainnet,
                    network_id: ChainId::MAINNET,
                    gateway: GatewayClient::mainnet(gateway_timeout).with_api_key(api_key),
                    database: data_directory.join("mainnet.sqlite"),
                    l1_core_address: H160::from(core_addr::MAINNET),
                },
                NetworkConfig::SepoliaTestnet => Self {
                    network: Chain::SepoliaTestnet,
                    network_id: ChainId::SEPOLIA_TESTNET,
                    gateway: GatewayClient::sepolia_testnet(gateway_timeout).with_api_key(api_key),
                    database: data_directory.join("testnet-sepolia.sqlite"),
                    l1_core_address: H160::from(core_addr::SEPOLIA_TESTNET),
                },
                NetworkConfig::SepoliaIntegration => Self {
                    network: Chain::SepoliaIntegration,
                    network_id: ChainId::SEPOLIA_INTEGRATION,
                    gateway: GatewayClient::sepolia_integration(gateway_timeout)
                        .with_api_key(api_key),
                    database: data_directory.join("integration-sepolia.sqlite"),
                    l1_core_address: H160::from(core_addr::SEPOLIA_INTEGRATION),
                },
                NetworkConfig::Custom {
                    gateway,
                    feeder_gateway,
                    chain_id,
                } => Self::configure_custom(
                    gateway,
                    feeder_gateway,
                    chain_id,
                    data_directory,
                    api_key,
                    gateway_timeout,
                )
                .await
                .context("Configuring custom network")?,
            };

            Ok(context)
        }

        /// Creates a [PathfinderContext] for a custom network. Provides
        /// additional verification by checking for a proxy gateway by
        /// comparing against L1 starknet address against of
        /// the known networks.
        async fn configure_custom(
            gateway: Url,
            feeder: Url,
            chain_id: String,
            data_directory: &Path,
            api_key: Option<String>,
            gateway_timeout: Duration,
        ) -> anyhow::Result<Self> {
            use pathfinder_crypto::Felt;
            use starknet_gateway_client::GatewayApi;

            let gateway = GatewayClient::with_urls(gateway, feeder, gateway_timeout)
                .context("Creating gateway client")?
                .with_api_key(api_key);

            let network_id =
                ChainId(Felt::from_be_slice(chain_id.as_bytes()).context("Parsing chain ID")?);

            let l1_core_address = gateway
                .eth_contract_addresses()
                .await
                .context("Downloading starknet L1 address from gateway for proxy check")?
                .starknet
                .0;

            // Check for proxies by comparing the core address against those of the known
            // networks.
            let network = match l1_core_address.as_bytes() {
                x if x == core_addr::MAINNET => Chain::Mainnet,
                x if x == core_addr::SEPOLIA_TESTNET => Chain::SepoliaTestnet,
                x if x == core_addr::SEPOLIA_INTEGRATION => Chain::SepoliaIntegration,
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
            Chain::SepoliaTestnet | Chain::SepoliaIntegration => EthereumChain::Sepolia,
            Chain::Custom => unreachable!("Already checked against"),
        };

        anyhow::ensure!(
            ethereum == expected,
            "Incorrect Ethereum network detected. Found {ethereum:?} but expected {expected:?} \
             for {} Starknet",
            starknet
        );
    }

    Ok(())
}

async fn verify_database(
    storage: &Storage,
    network: Chain,
    gateway_client: &starknet_gateway_client::Client,
) -> anyhow::Result<()> {
    let storage = storage.clone();
    let db_genesis = tokio::task::spawn_blocking(move || {
        let mut conn = storage.connection().context("Create database connection")?;
        let tx = conn.transaction().context("Create database transaction")?;

        tx.block_id(BlockNumber::GENESIS.into())
    })
    .await
    .context("Joining database task")?
    .context("Fetching genesis hash from database")?
    .map(|x| x.1);

    if let Some(database_genesis) = db_genesis {
        use pathfinder_common::consts::{
            MAINNET_GENESIS_HASH,
            SEPOLIA_INTEGRATION_GENESIS_HASH,
            SEPOLIA_TESTNET_GENESIS_HASH,
        };

        let db_network = match database_genesis {
            MAINNET_GENESIS_HASH => Chain::Mainnet,
            SEPOLIA_TESTNET_GENESIS_HASH => Chain::SepoliaTestnet,
            SEPOLIA_INTEGRATION_GENESIS_HASH => Chain::SepoliaIntegration,
            _ => Chain::Custom,
        };

        match (network, db_network) {
            (Chain::Custom, _) => {
                // Verify against gateway.
                let (_, gateway_hash) = gateway_client
                    .block_header(BlockNumber::GENESIS.into())
                    .await
                    .context("Downloading genesis block from gateway for database verification")?;

                anyhow::ensure!(
                    database_genesis == gateway_hash,
                    "Database genesis block does not match gateway. {} != {}",
                    database_genesis,
                    gateway_hash
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
