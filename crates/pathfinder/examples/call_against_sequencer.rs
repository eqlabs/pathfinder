use futures::future::TryFutureExt;
use jsonrpsee::core::error::Error;
use pathfinder_lib::{
    rpc::types::{request::Call, BlockHashOrTag},
    sequencer::ClientApi,
};
use tokio::io::AsyncBufReadExt;

use tracing::{debug, warn};

/// Tool for calling call locally while also asking sequencer for the result
/// and comparing the results.
///
/// Reads stdin lines for rpc api payload equivalents, processes the request locally and on the
/// sequencer serially. The comparison done between the results is done at the level of rpc
/// response, errors are compared as strings.
#[tokio::main]
async fn main() {
    if std::env::args().count() != 2 {
        eprintln!("USAGE: call_against_sequencer DB_PATH");
        eprintln!();
        eprintln!("For example:");
        eprintln!("echo '[\
            {{\
                 \"calldata\":[\"0x5\"],\
                 \"contract_address\":\"0x019245f0f49d23f2379d3e3f20d1f3f46207d1c4a1d09cac8dd50e8d528aabe1\",\
                 \"entry_point_selector\":\"0x026813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0\"\
             }},\
             \"0x7d328a71faf48c5c3857e99f20a77b18522480956d1cd5bff1ff2df3c8b427b\"\
            ]' | \\");
        eprintln!("  cargo run --example call_against_sequencer database.sqlite");
        eprintln!(
            "Example payload is for executing get_value on address 0x5 of a test.cairo \
             contract found in goerli networks first block. The call should return 0x22b."
        );
        std::process::exit(1);
    }

    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "debug");
    }

    tracing_subscriber::fmt::init();

    // non-configurable options, which might become command line options:
    let network = pathfinder_lib::core::Chain::Goerli;

    let db_file = std::env::args()
        .nth(1)
        .expect("Missing 1st argument: path to database");

    // we do not need to migrate, so maybe we don't migrate
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();

    let (handle, jh) = pathfinder_lib::cairo::ext_py::start(
        db_file.into(),
        std::num::NonZeroUsize::new(1).unwrap(),
        async move {
            // we expect the channel getting closed, but it doesn't really matter, just any
            // awaitable signal will work
            let _: Result<(), _> = stop_rx.await;
        },
        pathfinder_lib::core::Chain::Goerli,
    )
    .await
    .unwrap();

    let sequencer = pathfinder_lib::sequencer::Client::new(network).unwrap();

    let mut buffer = String::new();
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());

    loop {
        buffer.clear();
        let read = stdin.read_line(&mut buffer).await.unwrap();
        if read == 0 {
            break;
        }

        let args = serde_json::from_str::<NamedArgs>(&buffer)
            .expect("Failed to parse json-rpc alike payload on a single line");

        let seq = sequencer
            .call(args.request.clone().into(), args.block_hash)
            .map_ok(|x| x.result)
            .map_err(Error::from);

        let local = handle
            .call(args.request, args.block_hash, None)
            .map_err(Error::from);

        let (local, seq) = tokio::join!(local, seq);

        match (local, seq) {
            (Ok(x), Ok(y)) if x == y => {
                debug!(response=?x, "got equal to sequencer response");
            }
            (Ok(our), Ok(sequencer)) => {
                warn!(?our, ?sequencer, "got different ok responses");
            }
            (Err(our), Ok(sequencer)) => {
                warn!(%our, ?sequencer, "we errored but sequencer did not");
            }
            (Ok(our), Err(sequencer)) => {
                warn!(?our, %sequencer, "we didn't error but sequencer did");
            }
            (Err(error), Err(s)) if error.to_string() == s.to_string() => {
                debug!(%error, "we errored the same!");
            }
            (Err(our), Err(sequencer)) => {
                warn!(%our, %sequencer, "we errored differently!");
            }
        }
    }

    // signal shutdown
    drop(stop_tx);

    jh.await.unwrap();
}

/// Copypasted from src/rpc.rs
#[derive(Debug, serde::Deserialize)]
pub struct NamedArgs {
    pub request: Call,
    pub block_hash: BlockHashOrTag,
}
