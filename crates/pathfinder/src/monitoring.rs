use std::sync::atomic::AtomicBool;

use metrics_exporter_prometheus::PrometheusHandle;
use warp::Filter;

/// Spawns a server which hosts `/health`, `/ready` and `/metrics` endpoints.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
    readiness: std::sync::Arc<AtomicBool>,
    prometheus_handle: PrometheusHandle,
) -> tokio::task::JoinHandle<()> {
    let server = warp::serve(routes(readiness, prometheus_handle));
    let server = server.bind(addr);

    tokio::spawn(async move { server.await })
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
    warp::get()
        .and(warp::path!("health"))
        .and_then(|| async move {
            Ok::<_, std::convert::Infallible>(
                warp::http::Response::builder()
                    .header(warp::http::header::CONTENT_TYPE, "application/json")
                    .body("{\"healthy\":\"HEALTHY\"}"),
            )
        })
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
                true => Ok::<_, std::convert::Infallible>(
                    warp::http::Response::builder()
                        .header(warp::http::header::CONTENT_TYPE, "application/json")
                        .body("{\"ready\":\"READY\"}"),
                ),
                false => Ok::<_, std::convert::Infallible>(
                    warp::http::Response::builder()
                        .status(warp::http::StatusCode::SERVICE_UNAVAILABLE)
                        .header(warp::http::header::CONTENT_TYPE, "application/json")
                        .body("{\"ready\":\"NOT READY\"}"),
                ),
            }
        })
}

/// Returns Prometheus metrics snapshot at `/metrics`.
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

    #[tokio::test]
    async fn health() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness, handle);
        let response = warp::test::request().path("/health").reply(&filter).await;

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers().get(warp::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.body(), "{\"healthy\":\"HEALTHY\"}");
    }

    #[tokio::test]
    async fn ready() {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness.clone(), handle);
        let response = warp::test::request().path("/ready").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(warp::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.body(), "{\"ready\":\"NOT READY\"}");

        readiness.store(true, std::sync::atomic::Ordering::Relaxed);
        let response = warp::test::request().path("/ready").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers().get(warp::http::header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(response.body(), "{\"ready\":\"READY\"}");
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
        let filter = super::routes(readiness.clone(), handle);
        let response = warp::test::request().path("/metrics").reply(&filter).await;

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.body(), "# TYPE x counter\nx 123\n\n");
    }
}
