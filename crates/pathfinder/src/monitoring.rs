use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use metrics_exporter_prometheus::PrometheusHandle;

/// Spawns a server which hosts a `/health` endpoint.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
    readiness: Arc<AtomicBool>,
    prometheus_handle: PrometheusHandle,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = axum::Router::new()
        .route("/health", axum::routing::get(health_route))
        .route("/ready", axum::routing::get(ready_route))
        .route("/metrics", axum::routing::get(metrics_route))
        .with_state((readiness, prometheus_handle));
    let server = axum::Server::bind(&addr.into()).serve(app.into_make_service());
    let addr = server.local_addr();
    let spawn = tokio::spawn(async move { server.await.expect("server error") });
    (addr, spawn)
}

/// Always returns `Ok(200)` at `/health`.
async fn health_route() -> http::StatusCode {
    http::StatusCode::OK
}

/// Returns `Ok` if `readiness == true`, or `SERVICE_UNAVAILABLE` otherwise.
async fn ready_route(
    axum::extract::State((readiness, _)): axum::extract::State<(Arc<AtomicBool>, PrometheusHandle)>,
) -> http::StatusCode {
    if readiness.load(std::sync::atomic::Ordering::Relaxed) {
        http::StatusCode::OK
    } else {
        http::StatusCode::SERVICE_UNAVAILABLE
    }
}

/// Returns Prometheus metrics snapshot at `/metrics`.
async fn metrics_route(
    axum::extract::State((_, handle)): axum::extract::State<(Arc<AtomicBool>, PrometheusHandle)>,
) -> String {
    handle.render()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    use metrics_exporter_prometheus::PrometheusBuilder;

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
        let (addr, _) = super::spawn_server(([127, 0, 0, 1], 0), readiness.clone(), handle).await;
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
        let (addr, _) = super::spawn_server(([127, 0, 0, 1], 0), readiness.clone(), handle).await;
        let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        wait_healthy(&client, url.clone()).await;

        let url = url.join("ready").unwrap();
        let resp = client.get(url.clone()).send().await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::SERVICE_UNAVAILABLE);

        readiness.store(true, std::sync::atomic::Ordering::Relaxed);
        let resp = client.get(url).send().await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
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
        let (addr, _) = super::spawn_server(([127, 0, 0, 1], 0), readiness.clone(), handle).await;
        let url = reqwest::Url::parse(&format!("http://{addr}")).unwrap();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        wait_healthy(&client, url.clone()).await;

        let url = url.join("metrics").unwrap();
        let resp = client.get(url).send().await.unwrap();

        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            String::from_utf8(resp.bytes().await.unwrap().to_vec()).unwrap(),
            "# TYPE x counter\nx 123\n\n"
        );
    }
}
