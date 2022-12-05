pub mod middleware {
    use jsonrpsee::core::middleware::Middleware;

    #[derive(Debug, Clone)]
    pub struct RpcMetricsMiddleware;

    impl Middleware for RpcMetricsMiddleware {
        type Instant = ();

        fn on_request(&self) -> Self::Instant {}

        fn on_call(&self, name: &str) {
            metrics::increment_counter!("rpc_method_calls_total", "method" => name.to_owned());
        }

        fn on_result(&self, name: &str, success: bool, _started_at: Self::Instant) {
            if !success {
                metrics::increment_counter!("rpc_method_calls_failed_total", "method" => name.to_owned());
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum MaybeRpcMetricsMiddleware {
        Middleware(RpcMetricsMiddleware),
        NoOp,
    }

    impl jsonrpsee::core::middleware::Middleware for MaybeRpcMetricsMiddleware {
        type Instant = ();

        fn on_request(&self) -> Self::Instant {}

        fn on_call(&self, name: &str) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => x.on_call(name),
                MaybeRpcMetricsMiddleware::NoOp => {}
            }
        }

        fn on_result(&self, name: &str, success: bool, started_at: Self::Instant) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => x.on_result(name, success, started_at),
                MaybeRpcMetricsMiddleware::NoOp => {}
            }
        }
    }
}
