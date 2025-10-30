use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;
use pathfinder_common::integration_testing::debug_create_port_marker_file;
use pathfinder_rpc::types::syncing::Syncing;
use pathfinder_rpc::SyncState;

#[derive(Clone)]
struct State {
    readiness: Arc<AtomicBool>,
    sync: Arc<SyncState>,
    prometheus: PrometheusHandle,
}

/// Spawns a server which hosts a `/health` endpoint.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
    readiness: Arc<AtomicBool>,
    sync_state: Arc<SyncState>,
    prometheus_handle: PrometheusHandle,
    data_directory: &Path,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_route))
        .route("/ready", axum::routing::get(ready_route))
        .route("/ready/synced", axum::routing::get(synced_route))
        .route("/metrics", axum::routing::get(metrics_route))
        .with_state(State {
            readiness,
            sync: sync_state,
            prometheus: prometheus_handle,
        });
    let listener = tokio::net::TcpListener::bind(addr.into()).await?;
    let addr = listener.local_addr()?;
    debug_create_port_marker_file("monitor", addr.port(), data_directory);
    let spawn = util::task::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .with_graceful_shutdown(util::task::cancellation_token().cancelled_owned())
            .await
            .expect("server error")
    });
    Ok((addr, spawn))
}

/// Always returns `Ok(200)` at `/health`.
async fn health_route() -> http::StatusCode {
    http::StatusCode::OK
}

/// Returns `Ok` if `readiness == true`, or `SERVICE_UNAVAILABLE` otherwise.
async fn ready_route(axum::extract::State(state): axum::extract::State<State>) -> http::StatusCode {
    if state.readiness.load(std::sync::atomic::Ordering::Relaxed) {
        http::StatusCode::OK
    } else {
        http::StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Returns `Ok` if `readiness == true`, or `SERVICE_UNAVAILABLE` otherwise.
async fn synced_route(
    axum::extract::State(state): axum::extract::State<State>,
) -> http::StatusCode {
    if !state.readiness.load(std::sync::atomic::Ordering::Relaxed) {
        return http::StatusCode::SERVICE_UNAVAILABLE;
    }

    let status = { state.sync.status.read().await.clone() };
    match status {
        Syncing::Status(status)
            if status.highest.number.get() - status.current.number.get() < 6 =>
        {
            http::StatusCode::OK
        }
        _ => http::StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Returns Prometheus metrics snapshot at `/metrics`.
async fn metrics_route(axum::extract::State(state): axum::extract::State<State>) -> String {
    state.prometheus.render()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use metrics_exporter_prometheus::PrometheusBuilder;
    use pathfinder_common::BlockNumber;
    use pathfinder_rpc::types::syncing::{NumberedBlock, Status, Syncing};
    use pathfinder_rpc::SyncState;
    use tokio::sync::RwLock;

    async fn wait_healthy(client: &reqwest::Client, url: reqwest::Url) {
        let url = url.join("health").unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let resp = client.get(url.clone()).send().await.unwrap();
                if resp.status().is_success() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn health() {
        let readiness = Arc::new(AtomicBool::new(false));
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (addr, _) = super::spawn_server(
            ([127, 0, 0, 1], 0),
            readiness.clone(),
            Default::default(),
            handle,
            &PathBuf::default(),
        )
        .await
        .unwrap();
        let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        wait_healthy(&client, url).await;
    }

    #[tokio::test]
    async fn ready() {
        let readiness = Arc::new(AtomicBool::new(false));
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let (addr, _) = super::spawn_server(
            ([127, 0, 0, 1], 0),
            readiness.clone(),
            Default::default(),
            handle,
            &PathBuf::default(),
        )
        .await
        .unwrap();
        let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        wait_healthy(&client, url.clone()).await;

        let url = url.join("ready").unwrap();
        let resp = client.get(url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        readiness.store(true, std::sync::atomic::Ordering::Relaxed);
        let resp = client.get(url).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn synced() {
        let readiness = Arc::new(AtomicBool::new(false));
        let handle = PrometheusBuilder::new().build_recorder().handle();
        let sync_state = Arc::new(SyncState {
            status: RwLock::new(Syncing::False),
        });
        let (addr, _) = super::spawn_server(
            ([127, 0, 0, 1], 0),
            readiness.clone(),
            sync_state.clone(),
            handle,
            &PathBuf::default(),
        )
        .await
        .unwrap();
        let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        wait_healthy(&client, url.clone()).await;

        let url = url.join("ready/synced").unwrap();
        let resp = client.get(url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        readiness.store(true, std::sync::atomic::Ordering::Relaxed);
        let resp = client.get(url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        *sync_state.status.write().await = Syncing::Status(Status {
            starting: NumberedBlock {
                hash: Default::default(),
                number: BlockNumber::new_or_panic(0),
            },
            current: NumberedBlock {
                hash: Default::default(),
                number: BlockNumber::new_or_panic(1),
            },
            highest: NumberedBlock {
                hash: Default::default(),
                number: BlockNumber::new_or_panic(100),
            },
        });
        let resp = client.get(url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

        *sync_state.status.write().await = Syncing::Status(Status {
            starting: NumberedBlock {
                hash: Default::default(),
                number: BlockNumber::new_or_panic(0),
            },
            current: NumberedBlock {
                hash: Default::default(),
                number: BlockNumber::new_or_panic(98),
            },
            highest: NumberedBlock {
                hash: Default::default(),
                number: BlockNumber::new_or_panic(100),
            },
        });
        let resp = client.get(url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics() {
        use pathfinder_common::test_utils::metrics::ScopedRecorderGuard;

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Automatically deregister the recorder
        let _guard = ScopedRecorderGuard::new(recorder);

        // We don't care about the recorder being a singleton as the counter name here
        // does not interfere with any other "real" counter registered in
        // pathfinder or other tests
        let counter = metrics::register_counter!("x");
        counter.increment(123);

        let readiness = Arc::new(AtomicBool::new(false));
        let (addr, _) = super::spawn_server(
            ([127, 0, 0, 1], 0),
            readiness.clone(),
            Default::default(),
            handle,
            &PathBuf::default(),
        )
        .await
        .unwrap();
        let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        wait_healthy(&client, url.clone()).await;

        let url = url.join("metrics").unwrap();
        let resp = client.get(url).send().await.unwrap();

        assert_eq!(resp.status(), reqwest::StatusCode::OK);
        assert_eq!(
            String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap(),
            "# TYPE x counter\nx 123\n\n"
        );
    }
}
