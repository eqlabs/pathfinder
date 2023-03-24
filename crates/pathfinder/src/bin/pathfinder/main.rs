#![deny(rust_2018_idioms)]

use anyhow::Context;
use metrics_exporter_prometheus::PrometheusBuilder;
use pathfinder_common::{
    consts::VERGEN_GIT_SEMVER_LIGHTWEIGHT, Chain, ChainId, EthereumChain, StarknetBlockNumber,
};
use pathfinder_ethereum::provider::{EthereumTransport, HttpProvider};
use pathfinder_lib::{
    monitoring::{self},
    state,
};
use pathfinder_rpc::{cairo, metrics::logger::RpcMetricsLogger, SyncState};
use pathfinder_storage::Storage;
use starknet_gateway_client::ClientApi;
use starknet_gateway_types::pending::PendingData;
use std::net::SocketAddr;
use std::sync::{atomic::AtomicBool, Arc};
use tracing::info;

use crate::config::NetworkConfig;

mod config;
mod update;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    setup_tracing();

    let config = config::Config::parse();

    info!(
        // this is expected to be $(last_git_tag)-$(commits_since)-$(commit_hash)
        version = VERGEN_GIT_SEMVER_LIGHTWEIGHT,
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

    let network = match (config.network, ethereum.chain) {
        (Some(cfg), _) => cfg,
        (None, EthereumChain::Mainnet) => NetworkConfig::Mainnet,
        (None, EthereumChain::Goerli) => NetworkConfig::Testnet,
        (None, EthereumChain::Other(id)) => anyhow::bail!(
            r"Ethereum url must be from mainnet or goerli chains. Your provided url has chain ID {id}.

If you are trying to setup a custom StarkNet please use '--network custom'"
        ),
    };

    let (network, gateway_client, database_path, chain_id) = match network {
        NetworkConfig::Mainnet => (
            Chain::Mainnet,
            starknet_gateway_client::Client::mainnet(),
            "mainnet.sqlite",
            ChainId::MAINNET,
        ),
        NetworkConfig::Testnet => (
            Chain::Testnet,
            starknet_gateway_client::Client::mainnet(),
            "goerli.sqlite",
            ChainId::MAINNET,
        ),
        NetworkConfig::Testnet2 => (
            Chain::Testnet2,
            starknet_gateway_client::Client::mainnet(),
            "testnet2.sqlite",
            ChainId::MAINNET,
        ),
        NetworkConfig::Integration => (
            Chain::Integration,
            starknet_gateway_client::Client::mainnet(),
            "integration.sqlite",
            ChainId::MAINNET,
        ),
        NetworkConfig::Custom {
            gateway,
            feeder_gateway,
            chain_id,
        } => {
            let gateway_client =
                starknet_gateway_client::Client::with_urls(gateway, feeder_gateway)
                    .context("Creating gateway client")?;
            let chain_id =
                stark_hash::Felt::from_be_slice(chain_id.as_bytes()).context("Parsing chain ID")?;

            use pathfinder_common::consts::{
                INTEGRATION_GENESIS_HASH, MAINNET_GENESIS_HASH, TESTNET2_GENESIS_HASH,
                TESTNET_GENESIS_HASH,
            };

            let genesis = gateway_client
                .block(StarknetBlockNumber::GENESIS.into())
                .await
                .context("Downloading genesis block from gateway for proxy check")?
                .as_block()
                .context("Genesis block should not be pending")?
                .block_hash;

            let network = match genesis {
                MAINNET_GENESIS_HASH => {
                    tracing::info!("Proxy gateway for mainnet detected");
                    anyhow::ensure!(
                        ethereum.chain == EthereumChain::Mainnet,
                        "Proxy gateway for mainnet detected but the Ethereum URL is not on mainnet. Ethereum URL provided is on {:?}",
                        ethereum.chain
                    );

                    Chain::Mainnet
                }
                TESTNET_GENESIS_HASH => {
                    tracing::info!("Proxy gateway for testnet detected");
                    anyhow::ensure!(
                        ethereum.chain == EthereumChain::Goerli,
                        "Proxy gateway for testnet detected but the Ethereum URL is not on goerli. Ethereum URL provided is on {:?}",
                        ethereum.chain
                    );
                    Chain::Testnet
                }
                TESTNET2_GENESIS_HASH => {
                    tracing::info!("Proxy gateway for testnet2 detected");
                    anyhow::ensure!(
                        ethereum.chain == EthereumChain::Goerli,
                        "Proxy gateway for testnet2 detected but the Ethereum URL is not on goerli. Ethereum URL provided is on {:?}",
                        ethereum.chain
                    );
                    Chain::Testnet2
                }
                INTEGRATION_GENESIS_HASH => {
                    tracing::info!("Proxy gateway for integration detected");
                    anyhow::ensure!(
                        ethereum.chain == EthereumChain::Goerli,
                        "Proxy gateway for integration detected but the Ethereum URL is not on goerli. Ethereum URL provided is on {:?}",
                        ethereum.chain
                    );
                    Chain::Integration
                }
                _other => Chain::Custom,
            };

            (network, gateway_client, "custom.sqlite", ChainId(chain_id))
        }
    };
    let database_path = config.data_directory.join(database_path);

    // Setup and verify database
    let storage = Storage::migrate(database_path.clone(), config.sqlite_wal).unwrap();
    info!(location=?database_path, "Database migrated.");
    if let Some(database_genesis) = database_genesis_hash(&storage).await? {
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
                    .block(StarknetBlockNumber::GENESIS.into())
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

    let core_address = match network {
        Chain::Mainnet => pathfinder_ethereum::contract::MAINNET_ADDRESSES.core,
        Chain::Testnet => pathfinder_ethereum::contract::TESTNET_ADDRESSES.core,
        Chain::Integration => pathfinder_ethereum::contract::INTEGRATION_ADDRESSES.core,
        Chain::Testnet2 => pathfinder_ethereum::contract::TESTNET2_ADDRESSES.core,
        Chain::Custom => {
            let addresses = gateway_client
                .eth_contract_addresses()
                .await
                .context("Fetching StarkNet contract addresses for custom network")?;

            addresses.starknet.0
        }
    };

    // TODO: verify Ethereum core contract matches if we are on a custom network.

    let sync_state = Arc::new(SyncState::default());
    let pending_state = PendingData::default();
    let pending_interval = match config.poll_pending {
        true => Some(std::time::Duration::from_secs(5)),
        false => None,
    };

    // TODO: the error could be recovered, but currently it's required for startup. There should
    // not be other reason for the start to fail than python script not firing up.
    let (call_handle, cairo_handle) = cairo::ext_py::start(
        storage.path().into(),
        config.python_subprocesses,
        futures::future::pending(),
        network,
    )
    .await
    .context(
        "Creating python process for call handling. Have you setup our Python dependencies?",
    )?;

    let sync_handle = tokio::spawn(state::sync(
        storage.clone(),
        ethereum.transport.clone(),
        network,
        core_address,
        gateway_client.clone(),
        sync_state.clone(),
        state::l1::sync,
        state::l2::sync,
        pending_state.clone(),
        pending_interval,
        state::l2::BlockValidationMode::Strict,
    ));

    let shared = pathfinder_rpc::gas_price::Cached::new(Arc::new(ethereum.transport));

    let context = pathfinder_rpc::context::RpcContext::new(
        storage.clone(),
        sync_state.clone(),
        chain_id,
        gateway_client,
    )
    .with_call_handling(call_handle)
    .with_eth_gas_price(shared);
    let context = match config.poll_pending {
        true => context.with_pending_data(pending_state),
        false => context,
    };

    let (rpc_handle, local_addr) = pathfinder_rpc::RpcServer::new(config.rpc_address, context)
        .with_logger(RpcMetricsLogger)
        .run()
        .await
        .context("Starting the RPC server")?;

    info!("📡 HTTP-RPC server started on: {}", local_addr);

    let p2p_handle = start_p2p(chain_id, storage, sync_state).await?;

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

async fn database_genesis_hash(
    storage: &Storage,
) -> anyhow::Result<Option<pathfinder_common::StarknetBlockHash>> {
    use pathfinder_storage::StarknetBlocksTable;

    let storage = storage.clone();
    tokio::task::spawn_blocking(move || {
        let mut conn = storage.connection().context("Create database connection")?;
        let tx = conn.transaction().context("Create database transaction")?;

        StarknetBlocksTable::get_hash(&tx, StarknetBlockNumber::GENESIS.into())
    })
    .await
    .context("Fetching genesis hash from database")?
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
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
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
    transport: HttpProvider,
    chain: EthereumChain,
}

impl EthereumContext {
    /// Configure an [EthereumContext]'s transport and read the chain ID using it.
    async fn setup(url: reqwest::Url, password: Option<String>) -> anyhow::Result<Self> {
        let transport = HttpProvider::from_config(url, password).context("Creating transport")?;

        let chain = transport.chain().await.context(
            r"Determining Ethereum chain.
                            
Hint: Make sure the provided ethereum.url and ethereum.password are good.",
        )?;

        Ok(Self { transport, chain })
    }
}
