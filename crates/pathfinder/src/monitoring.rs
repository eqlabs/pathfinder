pub mod metrics;

use std::sync::atomic::AtomicBool;

use metrics_exporter_prometheus::PrometheusHandle;
use warp::Filter;

/// Spawns a server which hosts a `/health` endpoint.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
    readiness: std::sync::Arc<AtomicBool>,
    prometheus_handle: std::sync::Arc<PrometheusHandle>,
) -> tokio::task::JoinHandle<()> {
    let server = warp::serve(routes(readiness, prometheus_handle));
    let server = server.bind(addr);

    tokio::spawn(async move { server.await })
}

fn routes(
    readiness: std::sync::Arc<AtomicBool>,
    prometheus_handle: std::sync::Arc<PrometheusHandle>,
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
    handle: std::sync::Arc<PrometheusHandle>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::get()
        .and(warp::path!("metrics"))
        .map(move || -> std::sync::Arc<PrometheusHandle> { handle.clone() })
        .and_then(|handle: std::sync::Arc<PrometheusHandle>| async move {
            Ok::<_, std::convert::Infallible>(warp::http::Response::builder().body(handle.render()))
        })
}

#[cfg(test)]
mod tests {
    use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    lazy_static::lazy_static!(
        static ref PROMETHEUS_HANDLE: Arc<PrometheusHandle> = Arc::new(PrometheusBuilder::new().install_recorder().unwrap());
    );

    #[tokio::test]
    async fn health() {
        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness, PROMETHEUS_HANDLE.clone());
        let response = warp::test::request().path("/health").reply(&filter).await;

        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn ready() {
        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness.clone(), PROMETHEUS_HANDLE.clone());
        let response = warp::test::request().path("/ready").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);

        readiness.store(true, std::sync::atomic::Ordering::Relaxed);
        let response = warp::test::request().path("/ready").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics() {
        let handle = PROMETHEUS_HANDLE.clone();
        let counter = metrics::register_counter!("x");
        counter.increment(123);

        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness.clone(), handle);
        let response = warp::test::request().path("/metrics").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.body(), "# TYPE x counter\nx 123\n\n");
    }
}
