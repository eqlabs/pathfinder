use anyhow::Context;
use pathfinder_lib::{
    cairo,
    config::{self, EthereumConfig},
    ethereum, rpc, sequencer, state,
    storage::Storage,
};
use std::sync::Arc;
use tracing::info;
use web3::{transports::Http, Web3};

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
    let eth_transport = ethereum_transport(config.ethereum)
        .await
        .context("Creating Ethereum transport")?;

    let network_chain = ethereum::chain(&eth_transport)
        .await
        .context("Determining Ethereum chain")?;

    let database_path = match network_chain {
        ethereum::Chain::Mainnet => "mainnet.sqlite",
        ethereum::Chain::Goerli => "goerli.sqlite",
    };

    let storage = Storage::migrate(database_path.into()).unwrap();
    let sequencer = sequencer::Client::new(network_chain).unwrap();
    let sync_state = Arc::new(state::SyncState::default());

    let sync_handle = tokio::spawn(state::sync(
        storage.clone(),
        eth_transport,
        network_chain,
        sequencer.clone(),
        sync_state.clone(),
        state::L1SyncImpl,
        state::l2::sync,
    ));

    // TODO: the error could be recovered, but currently it's required for startup. There should
    // not be other reason for the start to fail than python script not firing up.
    let (call_handle, cairo_handle) = cairo::ext_py::start(
        storage.path().into(),
        std::num::NonZeroUsize::new(2).unwrap(),
        futures::future::pending(),
    )
    .await
    .context(
        "Creating python process for call handling. Have you setup our Python dependencies?",
    )?;

    let api = rpc::api::RpcApi::new(storage, sequencer, network_chain, sync_state)
        .with_call_handling(call_handle);

    let (rpc_handle, local_addr) =
        rpc::run_server(config.http_rpc_addr, api).context("Starting the RPC server")?;
    info!("📡 HTTP-RPC server started on: {}", local_addr);

    let update_handle = tokio::spawn(pathfinder_lib::update::poll_github_for_releases());

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

/// Creates an [Ethereum transport wrapper](ethereum::api::Web3EthImpl) from the configuration.
///
/// This includes setting:
/// - the [Url](reqwest::Url)
/// - the user-agent (if provided)
/// - the password (if provided)
async fn ethereum_transport(
    config: EthereumConfig,
) -> anyhow::Result<ethereum::api::Web3EthImpl<Http>> {
    let client = reqwest::Client::builder();
    let client = match config.user_agent {
        Some(user_agent) => client.user_agent(user_agent),
        None => client,
    }
    .build()
    .context("Creating HTTP client")?;

    let mut url = config.url;
    url.set_password(config.password.as_deref())
        .map_err(|_| anyhow::anyhow!("Setting password"))?;

    let client = Http::with_client(client, url);

    Ok(ethereum::api::Web3EthImpl(Web3::new(client)))
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
