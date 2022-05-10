use anyhow::Context;
use pathfinder_lib::{
    cairo, config,
    ethereum::{
        self,
        transport::{EthereumTransport, HttpTransport},
    },
    rpc, sequencer, state,
    storage::Storage,
};
use std::sync::Arc;
use tracing::info;

use std::{net::SocketAddr};
use std::convert::Infallible;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};

async fn healthz(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("ok")))
}

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
    let eth_transport =
        HttpTransport::from_config(config.ethereum).context("Creating Ethereum transport")?;

    let network_chain = eth_transport
        .chain()
        .await
        .context("Determining Ethereum chain")?;

    let database_path = config.data_directory.join(match network_chain {
        ethereum::Chain::Mainnet => "mainnet.sqlite",
        ethereum::Chain::Goerli => "goerli.sqlite",
    });
    let storage = Storage::migrate(database_path.clone()).unwrap();
    info!(location=?database_path, "Database migrated.");

    let sequencer = sequencer::Client::new(network_chain).unwrap();
    let sync_state = Arc::new(state::SyncState::default());

    let sync_handle = tokio::spawn(state::sync(
        storage.clone(),
        eth_transport,
        network_chain,
        sequencer.clone(),
        sync_state.clone(),
        state::l1::sync,
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

    let addr2 = SocketAddr::from(([0, 0, 0, 0], 8080));

    let make_svc = make_service_fn(|_conn| {
        // This is the `Service` that will handle the connection.
        // `service_fn` is a helper to convert a function that
        // returns a Response into a `Service`.
        async { Ok::<_, Infallible>(service_fn(healthz)) }
    });

    let srv2 = Server::bind(&addr2).serve(make_svc);

    info!("📡 Health server started on: {}", addr2);

    tokio::spawn(srv2);

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
