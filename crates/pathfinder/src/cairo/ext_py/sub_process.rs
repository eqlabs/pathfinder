//! Launching and communication with the subprocess

use super::{
    de::{ChildResponse, RefinedChildResponse, Status},
    ser::ChildCommand,
    CallFailure, Command, SharedReceiver, SubProcessEvent, SubprocessError, SubprocessExitReason,
};
use anyhow::Context;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{broadcast, mpsc};

/// Launches a python subprocess, and executes calls on it until shutdown is initiated.
///
/// If the python process is killed, reaping it and restarting new one is handled by [`super::start`],
/// similarly to spawning this as a task usually handled.
///
/// Launching happens in two stages, similar to the python process. Initially we only launch, then
/// read `"ready\n"` from the subprocess and after that enter the loop where we contend for the
/// commands.
pub(super) async fn launch_python(
    database_path: PathBuf,
    commands: SharedReceiver<Command>,
    status_updates: mpsc::Sender<SubProcessEvent>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> anyhow::Result<(u32, Option<std::process::ExitStatus>, SubprocessExitReason)> {
    let (mut child, pid, mut stdin, mut stdout, mut buffer) = match spawn(database_path).await {
        Ok(tuple) => tuple,
        Err(e) => {
            return Err(e.context("Failed to start python subprocess"));
        }
    };

    if status_updates
        .send(SubProcessEvent::ProcessLaunched(pid))
        .await
        .is_err()
    {
        drop(stdin);
        return Err(anyhow::anyhow!("Failed to notify of start"));
    }

    let mut command_buffer = Vec::new();

    // TODO: Why not have an outer loop to respawn a process fast? The idea occured during review.
    // Currently the "policy" over respawning is controlled by the "service" in `super::start`.
    let exit_reason = loop {
        let command = async {
            let mut locked = commands.lock().await;
            locked.recv().await
        };

        tokio::pin!(command);

        let (call, at_block, mut response) = tokio::select! {
            // locking is not cancellation safe BUT if the race is lost we don't retry so no
            // worries on that.
            maybe_command = &mut command => match maybe_command {
                Some(tuple) => tuple,
                None => break SubprocessExitReason::Shutdown,
            },
            _ = child.wait() => {
                // if the python process was killed while we were awaiting for new commands, it
                // would be zombie until we notice it has died. The wait can be called many times,
                // and it'll return immediatedly at the top level.
                break SubprocessExitReason::Death;
            }
            _ = shutdown_rx.recv() => {
                break SubprocessExitReason::Shutdown;
            },
        };

        if response.is_closed() {
            // quickly loadshed, as the caller has already left.
            continue;
        }

        command_buffer.clear();

        let cmd = ChildCommand {
            contract_address: &call.contract_address,
            calldata: &call.calldata,
            entry_point_selector: &call.entry_point_selector,
            at_block: &at_block,
        };

        if let Err(e) = serde_json::to_writer(std::io::Cursor::new(&mut command_buffer), &cmd) {
            eprintln!("Failed to render command {cmd:?} as json: {e:?}");
            let _ = response.send(Err(CallFailure::Internal(
                "Failed to render command as json",
            )));
            continue;
        }

        // using tokio::select to race against the shutdown_rx requires additional block to release
        // the &mut borrow on buffer to have it printed/logged
        let res = {
            // AsyncWriteExt::write_all used in the rpc_round is not cancellation safe, but
            // similar to above, if we lose the race, will kill the subprocess and get out.
            let rpc_op = rpc_round(&command_buffer, &mut stdin, &mut stdout, &mut buffer);
            tokio::pin!(rpc_op);

            tokio::select! {
                res = &mut rpc_op => res,
                _ = shutdown_rx.recv() => {
                    break SubprocessExitReason::Shutdown;
                },
                // no need to await for child dying here, because the event would close the childs
                // stdout and thus break our read_line and thus return a SubprocessError::IO and
                // we'd break out.
                _ = response.closed() => {
                    // attempt to guard against a call that essentially freezes up the python for
                    // how many minutes. by keeping our eye on this, we'll give the caller a
                    // chance to set timeouts, which will drop the futures.
                    //
                    // breaking out here will end up killing the python. it's probably the safest
                    // way to not cancel processing, because you can can't rely on SIGINT not being
                    // handled in a `expect Exception:` branch.
                    break SubprocessExitReason::Cancellation;
                }
            }
        };

        let (timings, status, sent_response) = match res {
            Ok(resp) => resp.into_messages(),
            Err(SubprocessError::InvalidJson(e)) => {
                // buffer still holds the response... might be good for debugging
                // this doesn't however mess up our line at once, so no worries.
                // TODO: log better
                eprintln!("failed to parse json: {e} on buffer: {buffer:?}");
                (
                    None,
                    Status::Failed,
                    Err(CallFailure::Internal("Invalid json received")),
                )
            }
            Err(SubprocessError::InvalidResponse) => {
                eprintln!("failed to understand parsed json on buffer: {buffer:?}");
                (
                    None,
                    Status::Failed,
                    Err(CallFailure::Internal("Invalid json received")),
                )
            }
            Err(SubprocessError::IO) => {
                let error = CallFailure::Internal("Input/output");
                let _ = response.send(Err(error));

                // TODO: consider if we'd just retry; put this back into the queue?
                break SubprocessExitReason::UnrecoverableIO;
            }
        };

        let _ = response.send(sent_response);

        let send_res = status_updates
            .send(SubProcessEvent::CommandHandled(pid, timings, status))
            .await;

        if send_res.is_err() {
            break SubprocessExitReason::ClosedChannel;
        }

        if !stdout.buffer().is_empty() {
            // some garbage was left in, it shouldn't have; there are extra printlns and we must
            // assume we've gone out of sync now.
            // FIXME: log this, hasn't happened.
            break SubprocessExitReason::UnrecoverableIO;
        }
    };

    // important to close up the stdin not to deadlock
    drop(stdin);
    drop(stdout);

    // give the subprocess a bit of time, since it might be less risky/better for sqlite to
    // exit/cleanup properly
    let sleep = tokio::time::sleep(std::time::Duration::from_millis(1000));
    tokio::pin!(sleep);

    let exit_status = tokio::select! {
        _ = &mut sleep => {
            match child.kill().await {
                Ok(()) => {}
                Err(e) => println!("Killing python subprocess failed, possibly a race? {e:?}"),
            }

            // kill already await the child, so there's not much to await here, we should just get the
            // fused response.
            match child.wait().await {
                Ok(status) => Some(status),
                Err(e) => {
                    eprintln!("wait on child pid failed: {e:?}");
                    None
                }
            }
        }
        exit_status = child.wait() => {
            exit_status.ok()
        }
    };

    Ok((pid, exit_status, exit_reason))
}

async fn spawn(
    database_path: PathBuf,
) -> anyhow::Result<(Child, u32, ChildStdin, BufReader<ChildStdout>, String)> {
    // there is not intentionally any std::fs::exists calls to avoid bringing any TOCTOU issues.
    let virtual_env = std::env::var_os("VIRTUAL_ENV")
        .context("VIRTUAL_ENV is not defined; has the user activated virtual environment")?;

    // FIXME: use choom, add something over /proc/self/oom_score_adj ?
    let mut python_exe = PathBuf::from(&virtual_env);
    python_exe.push("bin");
    python_exe.push("python");

    // we assume that VIRTUAL_ENV is at the base of the `py/` directory
    let mut call_py = PathBuf::from(&virtual_env);
    call_py.push("..");
    call_py.push("src");
    call_py.push("call.py");

    let mut command = tokio::process::Command::new(python_exe);

    command
        .arg(call_py)
        .arg(database_path)
        .env("VIRTUAL_ENV", virtual_env)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true);

    let _inherit_stderr = false;

    #[cfg(debug_assertions)]
    let _inherit_stderr = true;

    if _inherit_stderr {
        // in case the file doesn't exist it would be reported here ... probably cannot leave it
        // like this. exit code 2 is for the python file not being found.
        //
        // debug info is a great upside, but for example CTRL-C gets to the child processses as
        // well, and python will print a stacktrace when an SIGINT happens, which might be
        // confusing for users, who had just ran a rust program.
        command.stderr(std::process::Stdio::inherit());
    } else {
        command.stderr(std::process::Stdio::null());
    }

    let mut child = command
        .spawn()
        .context("Failed to spawn the new python process; this should only happen when the session is at it's process limit on unix.")?;

    // why care about the pid? it could be logged, and used to identify process activity, thought
    // these should be easy to spot otherwise as well.
    let pid = child.id().expect("The child pid should had been available after a successful start before waiting for it's status");

    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = child.stdout.take().expect("stdout was piped");

    // default buffer is fine for us ... but this is double buffering, for no good reason
    // it could actually be destroyed even between runs, because the buffer should be empty
    let mut stdout = BufReader::new(stdout);
    let mut buffer = String::new();

    // reasons for this part to error out:
    // - invalid schema version
    // - some other pythonic thing happens, for example, no call.py found
    let read = stdout
        .read_line(&mut buffer)
        .await
        .context("Failed to read 'ready' from python process")?;

    anyhow::ensure!(read == 6, "failed to read ready from python process");
    anyhow::ensure!(
        // buffer will contain the newline, which doesn't bother serde_json
        buffer.trim() == "ready",
        "failed to read ready from python process, read: {buffer:?}"
    );
    buffer.clear();

    Ok((child, pid, stdin, stdout, buffer))
}

/// Run a round of writing out the request, and reading a sane response type.
async fn rpc_round<'a>(
    cmd: &[u8],
    stdin: &mut tokio::process::ChildStdin,
    stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    buffer: &'a mut String,
) -> Result<RefinedChildResponse<'a>, SubprocessError> {
    // TODO: using a vectored write here would make most sense, but alas, advancing [IoSlice]'s is
    // still unstable. it could be copied, but we'd still lack `write_vectored_all`.
    //
    // note: write_all are not cancellation safe, and we call this from tokio::select! see callsite
    // for more discussion.
    stdin.write_all(cmd).await?;
    stdin.write_all(&b"\n"[..]).await?;
    stdin.flush().await?;

    // the read buffer is cleared very late to allow logging the output in case of an error.
    buffer.clear();

    let read = stdout.read_line(buffer).await?;

    if read == 0 {
        // EOF
        return Err(SubprocessError::IO);
    }

    let resp =
        serde_json::from_str::<ChildResponse>(buffer).map_err(SubprocessError::InvalidJson)?;

    resp.refine()
}
