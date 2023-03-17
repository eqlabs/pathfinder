pub mod middleware {
    use jsonrpsee::server::logger::Logger;

    #[derive(Debug, Clone)]
    pub struct RpcMetricsMiddleware;

    impl Logger for RpcMetricsMiddleware {
        type Instant = ();

        fn on_connect(
            &self,
            _remote_addr: std::net::SocketAddr,
            _request: &jsonrpsee::server::logger::HttpRequest,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
        }

        fn on_request(
            &self,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) -> Self::Instant {
        }

        fn on_call(
            &self,
            method_name: &str,
            _params: jsonrpsee::types::Params<'_>,
            _kind: jsonrpsee::server::logger::MethodKind,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
            metrics::increment_counter!("rpc_method_calls_total", "method" => method_name.to_owned());
        }

        fn on_result(
            &self,
            method_name: &str,
            success: bool,
            _started_at: Self::Instant,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
            if !success {
                metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name.to_owned());
            }
        }

        fn on_response(
            &self,
            _result: &str,
            _started_at: Self::Instant,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
        }

        fn on_disconnect(
            &self,
            _remote_addr: std::net::SocketAddr,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
        }
    }

    #[derive(Debug, Clone)]
    pub enum MaybeRpcMetricsMiddleware {
        Middleware(RpcMetricsMiddleware),
        NoOp,
    }

    impl jsonrpsee::server::logger::Logger for MaybeRpcMetricsMiddleware {
        type Instant = ();

        fn on_connect(
            &self,
            _remote_addr: std::net::SocketAddr,
            _request: &jsonrpsee::server::logger::HttpRequest,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
        }

        fn on_request(
            &self,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) -> Self::Instant {
        }

        fn on_call(
            &self,
            method_name: &str,
            params: jsonrpsee::types::Params<'_>,
            kind: jsonrpsee::server::logger::MethodKind,
            transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => {
                    x.on_call(method_name, params, kind, transport)
                }
                MaybeRpcMetricsMiddleware::NoOp => {}
            }
        }

        fn on_result(
            &self,
            method_name: &str,
            success: bool,
            started_at: Self::Instant,
            transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
            match self {
                MaybeRpcMetricsMiddleware::Middleware(x) => {
                    x.on_result(method_name, success, started_at, transport)
                }
                MaybeRpcMetricsMiddleware::NoOp => {}
            }
        }

        fn on_response(
            &self,
            _result: &str,
            _started_at: Self::Instant,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
        }

        fn on_disconnect(
            &self,
            _remote_addr: std::net::SocketAddr,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
        }
    }
}
