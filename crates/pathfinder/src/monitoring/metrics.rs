pub mod middleware {
    use jsonrpsee::core::middleware::Middleware;
    use metrics::increment_counter;
    use std::time::Instant;

    #[derive(Debug, Clone)]
    pub struct RpcMetricsMiddleware;

    impl Middleware for RpcMetricsMiddleware {
        type Instant = Instant;

        fn on_request(&self) -> Self::Instant {
            Instant::now()
        }

        fn on_call(&self, name: &str) {
            increment_counter!(format!("{name} call count"));
        }
    }

    #[derive(Debug, Clone)]
    pub enum MaybeRpcMetricsMiddleware {
        Middleware(RpcMetricsMiddleware),
        Noop,
    }

    impl jsonrpsee::core::middleware::Middleware for MaybeRpcMetricsMiddleware {
        type Instant = std::time::Instant;

        fn on_request(&self) -> Self::Instant {
            std::time::Instant::now()
        }

        fn on_call(&self, name: &str) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => x.on_call(name),
                MaybeRpcMetricsMiddleware::Noop => {}
            }
        }
    }
}
