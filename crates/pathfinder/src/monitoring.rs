use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;

use metrics_exporter_prometheus::PrometheusHandle;
use warp::Filter;

/// Spawns a server which hosts a `/health` endpoint.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
    readiness: std::sync::Arc<AtomicBool>,
    prometheus_handle: PrometheusHandle,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server = warp::serve(routes(readiness, prometheus_handle));
    let (addr, server) = server.bind_ephemeral(addr);

    (addr, tokio::spawn(server))
}

fn routes(
    readiness: std::sync::Arc<AtomicBool>,
    prometheus_handle: PrometheusHandle,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    health_route()
        .or(ready_route(readiness))
        .or(metrics_route(prometheus_handle))
}

/// Always returns `Ok(200)` at `/health`.
fn health_route() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::get().and(warp::path!("health")).map(warp::reply)
}

/// Returns `Ok` if `readiness == true`, or `SERVICE_UNAVAILABLE` otherwise.
fn ready_route(
    readiness: std::sync::Arc<AtomicBool>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path!("ready"))
        .map(move || -> std::sync::Arc<AtomicBool> { readiness.clone() })
        .and_then(|readiness: std::sync::Arc<AtomicBool>| async move {
            match readiness.load(std::sync::atomic::Ordering::Relaxed) {
                true => Ok::<_, std::convert::Infallible>(warp::http::StatusCode::OK),
                false => Ok(warp::http::StatusCode::SERVICE_UNAVAILABLE),
            }
        })
}

/// Returns Prometheus merics snapshot at `/metrics`.
fn metrics_route(
    handle: PrometheusHandle,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path!("metrics"))
        .map(move || -> PrometheusHandle { handle.clone() })
        .and_then(|handle: PrometheusHandle| async move {
            Ok::<_, std::convert::Infallible>(warp::http::Response::builder().body(handle.render()))
        })
}

#[cfg(test)]
mod tests {
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

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

        // We don't care about the recorder being a singleton as the counter name here does not
        // interfere with any other "real" counter registered in pathfinder or other tests
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
