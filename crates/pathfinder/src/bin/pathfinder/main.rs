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
use pathfinder_rpc::{cairo, metrics::middleware::RpcMetricsMiddleware, SyncState};
use pathfinder_storage::{JournalMode, Storage};
use starknet_gateway_client::ClientApi;
use starknet_gateway_types::pending::PendingData;
use std::sync::{atomic::AtomicBool, Arc};
use tracing::info;

mod config;
mod update;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    setup_tracing();

    let config = config::Configuration::parse_cmd_line().context("Parsing configuration")?;

    info!(
        // this is expected to be $(last_git_tag)-$(commits_since)-$(commit_hash)
        version = VERGEN_GIT_SEMVER_LIGHTWEIGHT,
        "🏁 Starting node."
    );

    permission_check(&config.data_directory)?;

    let pathfinder_ready = match config.monitoring_addr {
        Some(monitoring_addr) => {
            let ready = Arc::new(AtomicBool::new(false));
            let prometheus_handle = PrometheusBuilder::new()
                .install_recorder()
                .context("Creating Prometheus recorder")?;
            let _jh =
                monitoring::spawn_server(monitoring_addr, ready.clone(), prometheus_handle).await;
            Some(ready)
        }
        None => None,
    };

    let eth_transport = HttpProvider::from_config(
        config.ethereum.url.clone(),
        config.ethereum.password.clone(),
    )
    .context("Creating Ethereum transport")?;
    let ethereum_chain = eth_transport.chain().await.context(
        r"Determine Ethereum chain.
                        
Hint: Make sure the provided ethereum.url and ethereum.password are good.",
    )?;

    // Note that network testnet2 integration are mutually exclusive, which is already
    // checked in the config builder.
    let network = match config.network {
        Some(network) => match network.as_str() {
            "mainnet" => Chain::Mainnet,
            "testnet" => Chain::Testnet,
            "testnet2" => Chain::Testnet2,
            "integration" => Chain::Integration,
            "custom" => Chain::Custom,
            other => {
                anyhow::bail!("{other} is not a valid network selection. Please specify one of: mainnet, testnet, testnet2, integration or custom.")
            }
        },
        // Defaults if not specified
        None => match ethereum_chain {
            EthereumChain::Mainnet => Chain::Mainnet,
            EthereumChain::Goerli => Chain::Testnet,
            EthereumChain::Other(id) => anyhow::bail!(
                r"Ethereum url must be from mainnet or goerli chains. The given url has chain ID {id}.
    
If you are trying to setup a custom StarkNet please use '--network custom',
            "
            ),
        },
    };

    // Split custom config as they're required by separate parts.
    let (custom_gateway_urls, custom_chain_id) = match config.custom_gateway {
        Some((gateway, feeder, chain_id)) => (Some((gateway, feeder)), Some(chain_id)),
        None => (None, None),
    };

    let gateway_client = match (network, custom_gateway_urls) {
        (Chain::Custom, None) => {
            anyhow::bail!(
                "'--network custom' requires setting '--gateway-url' and '--feeder-gateway-url'."
            );
        }
        (Chain::Custom, Some((gateway, feeder))) => {
            starknet_gateway_client::Client::with_urls(gateway, feeder)
                .context("Creating gateway client")?
        }
        (_, Some(_)) => anyhow::bail!(
            "'--gateway-url' and '--feeder-gateway-url' are only valid with '--network custom'"
        ),
        (Chain::Mainnet, None) => starknet_gateway_client::Client::mainnet(),
        (Chain::Testnet, None) => starknet_gateway_client::Client::testnet(),
        (Chain::Testnet2, None) => starknet_gateway_client::Client::testnet2(),
        (Chain::Integration, None) => starknet_gateway_client::Client::integration(),
    };

    // Get database path before we mutate network.
    let database_path = config.data_directory.join(match network {
        Chain::Mainnet => "mainnet.sqlite",
        Chain::Testnet => "goerli.sqlite",
        Chain::Testnet2 => "testnet2.sqlite",
        Chain::Integration => "integration.sqlite",
        Chain::Custom => "custom.sqlite",
    });

    // Check for known proxy network
    let network = match network {
        Chain::Custom => {
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

            match genesis {
                MAINNET_GENESIS_HASH => {
                    tracing::info!("Proxy for mainnet detected");
                    Chain::Mainnet
                }
                TESTNET_GENESIS_HASH => {
                    tracing::info!("Proxy for testnet detected");
                    Chain::Testnet
                }
                TESTNET2_GENESIS_HASH => {
                    tracing::info!("Proxy for testnet2 detected");
                    Chain::Testnet2
                }
                INTEGRATION_GENESIS_HASH => {
                    tracing::info!("Proxy for integration detected");
                    Chain::Integration
                }
                _other => Chain::Custom,
            }
        }
        other => other,
    };

    // Setup and verify database
    let journal_mode = match config.sqlite_wal {
        false => JournalMode::Rollback,
        true => JournalMode::WAL,
    };
    let storage = Storage::migrate(database_path.clone(), journal_mode).unwrap();
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
        eth_transport.clone(),
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

    let shared = pathfinder_rpc::gas_price::Cached::new(Arc::new(eth_transport));

    let chain_id = match network {
        Chain::Mainnet => ChainId::MAINNET,
        Chain::Testnet => ChainId::TESTNET,
        Chain::Testnet2 => ChainId::TESTNET2,
        Chain::Integration => ChainId::INTEGRATION,
        Chain::Custom => {
            let chain_id =
                custom_chain_id.expect("Custom chain ID must be set for --network custom");
            let chain_id =
                stark_hash::Felt::from_be_slice(chain_id.as_bytes()).context("Parsing chain ID")?;

            ChainId(chain_id)
        }
    };

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

    let (rpc_handle, local_addr) = pathfinder_rpc::RpcServer::new(config.http_rpc_addr, context)
        .with_middleware(RpcMetricsMiddleware)
        .run()
        .await
        .context("Starting the RPC server")?;

    info!("📡 HTTP-RPC server started on: {}", local_addr);

    let p2p_handle = start_p2p(chain_id, storage, sync_state).await?;

    let update_handle = tokio::spawn(update::poll_github_for_releases());

    // We are now ready.
    if let Some(ready) = pathfinder_ready {
        ready.store(true, std::sync::atomic::Ordering::Relaxed);
    }

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
        _result = rpc_handle => {
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
