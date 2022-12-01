//! Starting and maintaining processes, and the main entry point

use super::{sub_process::launch_python, Command, Handle, SharedReceiver, SubProcessEvent};
use anyhow::Context;
use pathfinder_common::Chain;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, Mutex};
use tracing::Instrument;
use tracing::{info, trace, warn};

/// Starts to maintain a pool of `count` sub-processes which execute the calls.
///
/// In general, the launching currently assumes `python3` is a compatible Python
/// interpreter in an environment where our Python dependencies are set up properly.
///
/// This can usually be done in two ways:
/// - Creating a virtualenv, installing dependencies in that and activating it (as described
/// in `$REPO_ROOT/py/README.md`)
/// - By installing Python dependencies in a way that the _global_ `python3` interpreter can
/// import them.
///
/// Returns an error if executing calls in a sub-process is not supported.
#[tracing::instrument(name = "ext_py", skip_all, fields(%count))]
pub async fn start(
    database_path: PathBuf,
    count: std::num::NonZeroUsize,
    stop_flag: impl std::future::Future<Output = ()> + Send + 'static,
    chain: Chain,
) -> anyhow::Result<(Handle, tokio::task::JoinHandle<()>)> {
    use futures::stream::StreamExt;

    // channel sizes are conservative but probably enough for many workers; should investigate mpmc
    // if the lock overhead on command_rx before making these deeper.
    let (command_tx, command_rx) = mpsc::channel(1);
    let (status_tx, mut status_rx) = mpsc::channel(1);
    // this will never need to become deeper
    let (child_shutdown_tx, _) = broadcast::channel(1);
    let command_rx: SharedReceiver<(Command, tracing::Span)> = Arc::new(Mutex::new(command_rx));

    let metrics = Metrics::register();

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
                    metrics.increment_launched();
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
        chain: chain.into(),
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
                            let next = joinhandles.next().await;

                            match next {
                                Some(res) => { on_joined_subprocess(res, &metrics); },
                                None => break,
                            }
                        }
                        info!("Shutdown complete");
                        return;
                    }
                    Some(evt) = status_rx.recv() => {
                        match evt {
                            SubProcessEvent::ProcessLaunched(_) => {
                                metrics.increment_launched();
                            },
                        }
                    },
                    Some(res) = joinhandles.next() => {
                        let allow_spawn_right_away = on_joined_subprocess(res, &metrics);
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

/// Returns if a new subprocess should be launched without wait
fn on_joined_subprocess(
    res: Result<Result<super::SubprocessExitInfo, anyhow::Error>, tokio::task::JoinError>,
    metrics: &Metrics,
) -> bool {
    match res {
        Ok(Ok((pid, exit_status, exit_reason))) => {
            info!(%pid, ?exit_status, ?exit_reason, "Subprocess exited");
            metrics.increment_for_exit(&exit_reason);
            // after this we can spawn right away
            true
        }
        Ok(Err(error)) => {
            warn!(error = %error, "Subprocess failed");
            metrics.increment_failed();
            // a bug, but it might be on the rust side, so spawn right away
            true
        }
        Err(join_error) => {
            // in shutdown the cancellation one could be raced if there'd be graceful shutdown and
            // tokio would be shut down.
            warn!(error = %join_error, "Subprocess exited unexpectedly");
            // something wrong with the subprocess, don't spawn right away
            false
        }
    }
}

static METRIC_LAUNCHED_PROCESSES: &str = "extpy_processes_launched_total";
static METRIC_EXITED_PROCESSES: &str = "extpy_processes_exited_total";
static METRIC_FAILED_PROCESSES: &str = "extpy_processes_failed_total";

struct Metrics {
    launched: metrics::Counter,
    failed: metrics::Counter,
}

impl Metrics {
    fn register() -> Self {
        let launched = metrics::register_counter!(METRIC_LAUNCHED_PROCESSES);
        metrics::describe_counter!(
            METRIC_LAUNCHED_PROCESSES,
            metrics::Unit::Count,
            "number of launched python subprocesses; equals sum of exited and failed subprocesses."
        );

        // exposing the Option<ExitStatus>: opaque, exit reason counts why our code ended up reacting
        // like this. failed variant catches all errors.
        for reason in super::SubprocessExitReason::all_labels() {
            metrics::register_counter!(METRIC_EXITED_PROCESSES, "reason" => reason);
        }
        metrics::describe_counter!(
            METRIC_EXITED_PROCESSES,
            metrics::Unit::Count,
            "number of normally exited subprocesses."
        );

        let failed = metrics::register_counter!(METRIC_FAILED_PROCESSES);
        metrics::describe_counter!(
            METRIC_FAILED_PROCESSES,
            metrics::Unit::Count,
            "number of abnormally, due to bug, exited subprocesses."
        );

        Metrics { launched, failed }
    }

    fn increment_launched(&self) {
        self.launched.increment(1);
    }

    fn increment_for_exit(&self, exit_reason: &super::SubprocessExitReason) {
        let why = exit_reason.as_label();
        metrics::increment_counter!(METRIC_EXITED_PROCESSES, "reason" => why);
    }

    fn increment_failed(&self) {
        self.failed.increment(1);
    }
}
