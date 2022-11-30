#![deny(rust_2018_idioms)]

use anyhow::Context;
use metrics_exporter_prometheus::PrometheusBuilder;
use pathfinder_common::{Chain, EthereumChain, StarknetBlockNumber};
use pathfinder_ethereum::transport::{EthereumTransport, HttpTransport};
use pathfinder_lib::sequencer::ClientApi;
use pathfinder_lib::{
    cairo,
    monitoring::{self, metrics::middleware::RpcMetricsMiddleware},
    rpc, sequencer, state,
    storage::{JournalMode, Storage},
};
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

    let config =
        config::Configuration::parse_cmd_line_and_cfg_file().context("Parsing configuration")?;

    info!(
        // this is expected to be $(last_git_tag)-$(commits_since)-$(commit_hash)
        version = env!("VERGEN_GIT_SEMVER_LIGHTWEIGHT"),
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

    let eth_transport = HttpTransport::from_config(
        config.ethereum.url.clone(),
        config.ethereum.password.clone(),
    )
    .context("Creating Ethereum transport")?;
    let ethereum_chain = eth_transport.chain().await.context(
        r"Determine Ethereum chain.
                        
Hint: Make sure the provided ethereum.url and ethereum.password are good.",
    )?;

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
        // Defaults if --network is not specified
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

    let gateway_client = match (network, config.custom_gateway, config.sequencer_url) {
        (Chain::Custom, None, _) => {
            anyhow::bail!(
                "'--network custom' requires setting '--gateway-url' and '--feeder-gateway-url'."
            );
        }
        (Chain::Custom, Some((gateway, feeder, _)), _) => {
            pathfinder_lib::sequencer::Client::with_urls(gateway, feeder)
                .context("Creating gateway client")?
        }
        (_, Some(_), _) => anyhow::bail!(
            "'--gateway-url' and '--feeder-gateway-url' are only valid with '--network custom'"
        ),
        (Chain::Mainnet, None, None) => sequencer::Client::mainnet(),
        (Chain::Testnet, None, None) => sequencer::Client::testnet(),
        (Chain::Testnet2, None, None) => sequencer::Client::testnet2(),
        (Chain::Integration, None, None) => sequencer::Client::integration(),
        (_, _, Some(sequencer_url)) => {
            pathfinder_lib::sequencer::Client::with_base_url(sequencer_url)
                .context("Creating gateway client")?
        }
    };

    // Setup and verify database
    let database_path = config.data_directory.join(match network {
        Chain::Mainnet => "mainnet.sqlite",
        Chain::Testnet => "goerli.sqlite",
        Chain::Testnet2 => "testnet2.sqlite",
        Chain::Integration => "integration.sqlite",
        Chain::Custom => "custom.sqlite",
    });
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
                    .context("Downloading genesis block from gateway")?
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
        Chain::Integration => pathfinder_ethereum::contract::TESTNET2_ADDRESSES.core,
        Chain::Testnet2 => pathfinder_ethereum::contract::INTEGRATION_ADDRESSES.core,
        Chain::Custom => {
            let addresses = gateway_client
                .eth_contract_addresses()
                .await
                .context("Fetching StarkNet contract addresses for custom network")?;

            addresses.starknet.0
        }
    };

    // TODO: verify Ethereum core contract matches if we are on a custom network.

    let sync_state = Arc::new(state::SyncState::default());
    let pending_state = state::PendingData::default();
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
    ));

    let shared = rpc::gas_price::Cached::new(Arc::new(eth_transport));

    let api = rpc::v01::api::RpcApi::new(storage, gateway_client, network, sync_state)
        .with_call_handling(call_handle)
        .with_eth_gas_price(shared);
    let api = match config.poll_pending {
        true => api.with_pending_data(pending_state),
        false => api,
    };

    let (rpc_handle, local_addr) = rpc::RpcServer::new(config.http_rpc_addr, api)
        .with_middleware(RpcMetricsMiddleware)
        .run()
        .await
        .context("Starting the RPC server")?;

    info!("📡 HTTP-RPC server started on: {}", local_addr);

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
    }

    Ok(())
}

async fn database_genesis_hash(
    storage: &Storage,
) -> anyhow::Result<Option<pathfinder_common::StarknetBlockHash>> {
    use pathfinder_lib::storage::StarknetBlocksTable;

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
