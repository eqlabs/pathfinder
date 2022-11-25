#![deny(rust_2018_idioms)]

use anyhow::Context;
use metrics_exporter_prometheus::PrometheusBuilder;
use pathfinder_common::{self, Chain, EthereumChain};
use pathfinder_ethereum::transport::{EthereumTransport, HttpTransport};
use pathfinder_lib::{
    cairo,
    monitoring::{self, metrics::middleware::RpcMetricsMiddleware},
    rpc, sequencer, state,
    storage::{JournalMode, Storage},
};
use std::sync::{atomic::AtomicBool, Arc};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "info");
    }

    setup_tracing();

    let config = pathfinder_config::Configuration::parse_cmd_line_and_cfg_file()
        .context("Parsing configuration")?;

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

    let eth_transport =
        HttpTransport::from_config(config.ethereum).context("Creating Ethereum transport")?;

    // have a special long form hint here because there should be a lot of questions coming up
    // about this one.
    let ethereum_chain = eth_transport.chain().await.context(
        "Determine Ethereum chain.

Hint: Make sure the provided ethereum.url and ethereum.password are good.",
    )?;

    let starknet_chain = match (ethereum_chain, config.integration, config.testnet2) {
        (EthereumChain::Mainnet, false, false) => Chain::Mainnet,
        (EthereumChain::Mainnet, _, _) => {
            anyhow::bail!("'--integration' and '--testnet2' flags are invalid on Ethereum mainnet");
        }
        (EthereumChain::Goerli, false, false) => Chain::Testnet,
        (EthereumChain::Goerli, false, true) => Chain::Testnet2,
        (EthereumChain::Goerli, true, true) => {
            anyhow::bail!("'--integration' and '--testnet2' flags cannot be used together")
        }
        (EthereumChain::Goerli, true, false) => Chain::Integration,
    };

    let database_path = config.data_directory.join(match starknet_chain {
        Chain::Mainnet => "mainnet.sqlite",
        Chain::Testnet => "goerli.sqlite",
        Chain::Testnet2 => "testnet2.sqlite",
        Chain::Integration => "integration.sqlite",
    });
    let journal_mode = match config.sqlite_wal {
        false => JournalMode::Rollback,
        true => JournalMode::WAL,
    };
    let storage = Storage::migrate(database_path.clone(), journal_mode).unwrap();
    info!(location=?database_path, "Database migrated.");
    verify_database_chain(&storage, starknet_chain).context("Verifying database")?;

    let sequencer = match config.sequencer_url {
        Some(url) => {
            info!(?url, "Using custom Sequencer address");
            let client = sequencer::Client::with_url(url).unwrap();
            let sequencer_chain = client.chain().await.unwrap();
            if sequencer_chain != starknet_chain {
                tracing::error!(sequencer=%sequencer_chain, ethereum=%starknet_chain, "Sequencer and Ethereum network mismatch");
                anyhow::bail!("Sequencer and Ethereum network mismatch. Sequencer is on {sequencer_chain} but Ethereum is on {starknet_chain}");
            }
            client
        }
        None => sequencer::Client::new(starknet_chain).unwrap(),
    };
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
        starknet_chain,
    )
    .await
    .context(
        "Creating python process for call handling. Have you setup our Python dependencies?",
    )?;

    let sync_handle = tokio::spawn(state::sync(
        storage.clone(),
        eth_transport.clone(),
        starknet_chain,
        sequencer.clone(),
        sync_state.clone(),
        state::l1::sync,
        state::l2::sync,
        pending_state.clone(),
        pending_interval,
    ));

    let shared = rpc::gas_price::Cached::new(Arc::new(eth_transport));

    let api = rpc::v01::api::RpcApi::new(storage, sequencer, starknet_chain, sync_state)
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

    let update_handle = tokio::spawn(pathfinder_lib::update::poll_github_for_releases());

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

/// Verifies that the database matches the expected chain; throws an error if it does not.
fn verify_database_chain(storage: &Storage, expected: Chain) -> anyhow::Result<()> {
    use pathfinder_lib::storage::StarknetBlocksTable;

    let mut connection = storage.connection().context("Create database connection")?;
    let transaction = connection
        .transaction()
        .context("Create database transaction")?;

    let db_chain = match StarknetBlocksTable::get_chain(&transaction)
        .context("Get chain from genesis block in the DB")?
    {
        Some(chain) => chain,
        None => return Ok(()),
    };

    anyhow::ensure!(
        db_chain == expected,
        "Database ({}) does not match the expected network ({})",
        db_chain,
        expected
    );

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
