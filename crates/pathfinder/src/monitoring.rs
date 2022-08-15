use std::sync::atomic::AtomicBool;

use warp::Filter;

/// Spawns a server which hosts a `/health` endpoint.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
    readiness: std::sync::Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let server = warp::serve(routes(readiness));
    let server = server.bind(addr);

    tokio::spawn(async move { server.await })
}

fn routes(
    readiness: std::sync::Arc<AtomicBool>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    health_route().or(ready_route(readiness))
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

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn health() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness);
        let response = warp::test::request().path("/health").reply(&filter).await;

        assert_eq!(response.status(), http::StatusCode::OK);
    }

    #[tokio::test]
    async fn ready() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let readiness = Arc::new(AtomicBool::new(false));
        let filter = super::routes(readiness.clone());
        let response = warp::test::request().path("/ready").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::SERVICE_UNAVAILABLE);

        readiness.store(true, std::sync::atomic::Ordering::Relaxed);
        let response = warp::test::request().path("/ready").reply(&filter).await;
        assert_eq!(response.status(), http::StatusCode::OK);
    }
}
