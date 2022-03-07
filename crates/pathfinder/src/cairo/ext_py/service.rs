//! Starting and maintaining processes, and the main entry point

use super::{sub_process::launch_python, Command, Handle, SharedReceiver, SubProcessEvent};
use anyhow::Context;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::Instrument;
use tracing::{info, trace, warn};

/// Starts to maintain a pool of `count` sub-processes which execute the calls.
///
/// In general, the launching currently assumes:
///
/// - user has entered the python virtual environment created for this project per instructions
/// under `$REPO_ROOT/py/README.md`
/// - `call.py` can be found from the `$VIRTUAL_ENV/../src/call.py`
/// - user has compatible python, 3.7+ should work just fine
///
/// Returns an error if executing calls in a sub-process is not supported.
#[tracing::instrument(name = "ext_py", skip_all, fields(%count))]
pub async fn start(
    database_path: PathBuf,
    count: std::num::NonZeroUsize,
    stop_flag: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<(Handle, tokio::task::JoinHandle<()>)> {
    use futures::stream::StreamExt;

    // channel sizes are conservative but probably enough for many workers; should investigate mpmc
    // if the lock overhead on command_rx before making these deeper.
    let (command_tx, command_rx) = mpsc::channel(1);
    let (status_tx, mut status_rx) = mpsc::channel(1);
    // this will never need to become deeper
    let (child_shutdown_tx, _) = broadcast::channel(1);
    let command_rx: SharedReceiver<(Command, tracing::Span)> = Arc::new(Mutex::new(command_rx));

    // TODO: might be better to use tokio's JoinSet?
    let mut joinhandles = futures::stream::FuturesUnordered::new();

    let jh = tokio::task::spawn(
        launch_python(
            database_path.clone(),
            Arc::clone(&command_rx),
            status_tx.clone(),
            child_shutdown_tx.subscribe(),
        )
        .in_current_span(),
    );

    joinhandles.push(jh);

    // race the process launched notification or the task completion from joinhandles
    tokio::select! {
        Some(evt) = status_rx.recv() => {
            match evt {
                SubProcessEvent::ProcessLaunched(_pid) => {
                    // good, now we can launch the other processes requested later
                },
                SubProcessEvent::CommandHandled(..) => {
                    unreachable!("First message must not be CommandHandled");
                },
            }
        },
        Some(res) = &mut joinhandles.next() => {
            match res {
                Ok(Ok(t)) => unreachable!("First subprocess should not have exited successfully: {:?}", t),
                // this is the failure to start
                Ok(Err(e)) => return Err(e),
                // this is the failure to join, panic or cancellation
                Err(e) => return Err(e).context("Launching first python executor"),
            }
        }
    };

    let handle = Handle {
        command_tx: command_tx.clone(),
    };

    let jh = tokio::task::spawn(
        async move {
            const WAIT_BEFORE_SPAWN: std::time::Duration = std::time::Duration::from_secs(1);

            // use a sleep activated periodically before launching new processes
            // not to overwhelm the system
            let wait_before_spawning = tokio::time::sleep(WAIT_BEFORE_SPAWN);
            tokio::pin!(wait_before_spawning);

            tokio::pin!(stop_flag);

            loop {
                let mut spawn = false;
                tokio::select! {
                    _ = &mut stop_flag => {
                        trace!("Starting shutdown");
                        // this should be enough to kick everyone off the locking, queue receiving
                        let _ = child_shutdown_tx.send(());

                        loop {
                            match joinhandles.next().await {
                                Some(Ok(_)) => {}
                                Some(Err(error)) => {
                                    // these should all be bugs
                                    warn!(%error, "Joined subprocess had failed");
                                },
                                None => break,
                            }
                        }
                        info!("Shutdown complete");
                        return;
                    }
                    Some(evt) = status_rx.recv() => {
                        match evt {
                            SubProcessEvent::ProcessLaunched(_) => {},
                            SubProcessEvent::CommandHandled(pid, timings, status) => {
                                trace!(%pid, ?status, ?timings, "Command handled");
                            },
                        }
                    },
                    Some(res) = joinhandles.next() => {
                        let allow_spawn_right_away = match res {
                            Ok(Ok((pid, exit_status, exit_reason))) => {
                                info!(%pid, ?exit_status, ?exit_reason, "Subprocess exited");
                                true
                            },
                            Ok(Err(error)) => {
                                warn!(error = %error, "Subprocess failed");
                                true
                            },
                            Err(join_error) => {
                                warn!(error = %join_error, "Subprocess exited unexpectedly");
                                false
                            },
                        };
                        // println!("one of our python processes have expired: {_maybe_info:?}");
                        // we should spawn it immediatedly if empty
                        spawn = allow_spawn_right_away && joinhandles.is_empty();
                    }
                    _ = &mut wait_before_spawning => {
                        // spawn if needed
                        spawn = count.get() > joinhandles.len();
                        wait_before_spawning
                            .as_mut()
                            .reset(tokio::time::Instant::now() + WAIT_BEFORE_SPAWN);
                    }
                }

                if spawn {
                    let jh = tokio::task::spawn(
                        launch_python(
                            database_path.clone(),
                            Arc::clone(&command_rx),
                            status_tx.clone(),
                            child_shutdown_tx.subscribe(),
                        )
                        .in_current_span(),
                    );

                    joinhandles.push(jh);
                }
            }
        }
        .in_current_span(),
    );

    Ok((handle, jh))
}
