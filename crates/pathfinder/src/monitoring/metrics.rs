pub mod middleware {
    use jsonrpsee::core::middleware::Middleware;
    use std::time::Instant;

    #[derive(Debug, Clone)]
    pub struct RpcMetricsMiddleware;

    impl Middleware for RpcMetricsMiddleware {
        type Instant = Instant;

        fn on_request(&self) -> Self::Instant {
            Instant::now()
        }

        fn on_call(&self, _name: &str) {}
    }
}
