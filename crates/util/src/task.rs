use std::future::Future;
use std::sync::LazyLock;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub trait FutureOutputExt {
    fn cancelled() -> Self;
}

impl FutureOutputExt for () {
    fn cancelled() -> Self {}
}

impl<T> FutureOutputExt for anyhow::Result<T> {
    fn cancelled() -> Self {
        Err(anyhow::anyhow!("Cancelled due to graceful shutdown"))
    }
}

/// Spawns a future on the `tokio` runtime through a
/// [`tokio_util::task::TaskTracker`]. This ensures that upon graceful shutdown
/// the future will have already completed or will be cancelled in an orderly
/// fashion.
pub fn spawn<F>(file: &str, line: u32, future: F) -> tokio::task::JoinHandle<F::Output>
where
    F: Future + Send + 'static,
    F::Output: FutureOutputExt + Send + 'static,
{
    let Handle {
        task_tracker,
        cancellation_token,
        registry,
    } = HANDLE.clone();

    let key = format!("spawn {}:{}", file, line);

    // tracing::error!(%key);

    registry.insert(key.clone());

    task_tracker.spawn(async move {
        let x = tokio::select! {
            _ = cancellation_token.cancelled() => {
                F::Output::cancelled()
            }
            res = future => {
                res
            }
        };

        registry.remove(&key);

        x
    })
}

/// Runs the provided closure on a `tokio` thread where blocking is acceptable,
/// similarly to [`tokio::task::spawn_blocking`], however internally the closure
/// is spawned through a [`tokio_util::task::TaskTracker`] to ensure that it
/// will always be waited on and completed upon graceful shutdown.
///
/// A [`CancellationToken`] is provided to the closure to allow
/// for bailing out early in case of long running tasks when a graceful shutdown
/// is triggered. [`CancellationToken::is_cancelled`] should be used to perform
/// the check.
pub fn spawn_blocking<F, R>(file: &str, line: u32, f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce(CancellationToken) -> R + Send + 'static,
    R: Send + 'static,
{
    let Handle {
        task_tracker,
        cancellation_token,
        registry,
    } = HANDLE.clone();

    let key = format!("spawn_blocking {}:{}", file, line);

    // tracing::error!(%key);

    registry.insert(key.clone());

    task_tracker.spawn_blocking(move || {
        let x = f(cancellation_token);

        registry.remove(&key);

        x
    })
}

/// Runs the provided closure on an [`std::thread`] by calling
/// [`std::thread::spawn`].
///
/// A [`CancellationToken`] is provided to the closure to allow for bailing out
/// early in case of long running tasks when a graceful shutdown is triggered.
/// [`CancellationToken::is_cancelled`] should be used to perform the check.
///
/// ### Important
///
/// Caller must take care to ensure that the spawned thread is properly joined
/// or make sure that detachment is safe for the application.
pub fn spawn_std<F, R>(file: &str, line: u32, f: F) -> std::thread::JoinHandle<R>
where
    F: FnOnce(CancellationToken) -> R + Send + 'static,
    R: Send + 'static,
{
    let Handle {
        cancellation_token,
        registry,
        ..
    } = HANDLE.clone();

    let key = format!("spawn_std {}:{}", file, line);

    // tracing::error!(%key);

    registry.insert(key.clone());

    std::thread::spawn(move || {
        let x = f(cancellation_token);

        registry.remove(&key);

        x
    })
}

/// Returns a [`CancellationToken`] that can be used to check for graceful
/// shutdown.
pub fn cancellation_token() -> CancellationToken {
    HANDLE.clone().cancellation_token
}

pub mod tracker {
    use super::*;

    /// Close the task tracker and then **cancel all tracked futures**. See
    /// [`TaskTracker::close`] and [`CancellationToken::cancel`].
    pub fn close() {
        let Handle {
            cancellation_token, ..
        } = HANDLE.clone();
        cancellation_token.cancel();
    }

    /// Wait until task tracker is both closed and empty. See
    /// [`TaskTracker::wait`].
    pub async fn wait() {
        let Handle { task_tracker, .. } = HANDLE.clone();
        task_tracker.wait().await;
    }

    pub fn log_registry() {
        let Handle { registry, .. } = HANDLE.clone();
        tracing::error!("registry: {:#?}", registry);
    }
}

#[derive(Clone)]
struct Handle {
    task_tracker: TaskTracker,
    cancellation_token: CancellationToken,
    registry: std::sync::Arc<dashmap::DashSet<String>>,
}

static HANDLE: LazyLock<Handle> = LazyLock::new(|| Handle {
    task_tracker: TaskTracker::new(),
    cancellation_token: CancellationToken::new(),
    registry: std::sync::Arc::new(dashmap::DashSet::new()),
});
