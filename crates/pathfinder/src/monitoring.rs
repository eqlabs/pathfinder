use warp::Filter;

/// Spawns a server which hosts a `/health` endpoint.
pub async fn spawn_server(
    addr: impl Into<std::net::SocketAddr> + 'static,
) -> tokio::task::JoinHandle<()> {
    let health = health_filter();

    let server = warp::serve(health);
    let server = server.bind(addr);

    tokio::spawn(async move { server.await })
}

/// Always returns `Ok(200)` at `/health`.
fn health_filter() -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    warp::get().and(warp::path!("health")).map(warp::reply)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn health_is_200() {
        let filter = super::health_filter();
        let response = warp::test::request().path("/health").reply(&filter).await;

        assert_eq!(response.status(), 200);
    }
}
