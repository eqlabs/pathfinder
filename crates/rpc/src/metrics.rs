pub mod logger {
    use crate::module::split_version_prefix;
    use jsonrpsee::server::logger::Logger;

    #[derive(Debug, Clone)]
    pub struct RpcMetricsLogger;

    impl Logger for RpcMetricsLogger {
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
            match split_version_prefix(method_name) {
                Some((version, method_name)) => {
                    metrics::increment_counter!("rpc_method_calls_total", "method" => method_name, "version" => version)
                }
                None => {
                    metrics::increment_counter!("rpc_method_calls_total", "method" => method_name.to_owned())
                }
            }
        }

        fn on_result(
            &self,
            method_name: &str,
            success: bool,
            _started_at: Self::Instant,
            _transport: jsonrpsee::server::logger::TransportProtocol,
        ) {
            if !success {
                match split_version_prefix(method_name) {
                    Some((version, method_name)) => {
                        metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name, "version" => version)
                    }
                    None => {
                        metrics::increment_counter!("rpc_method_calls_failed_total", "method" => method_name.to_owned())
                    }
                }
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
    pub enum MaybeRpcMetricsLogger {
        Logger(RpcMetricsLogger),
        NoOp,
    }

    impl jsonrpsee::server::logger::Logger for MaybeRpcMetricsLogger {
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
                MaybeRpcMetricsLogger::Logger(x) => x.on_call(method_name, params, kind, transport),
                MaybeRpcMetricsLogger::NoOp => {}
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
                MaybeRpcMetricsLogger::Logger(x) => {
                    x.on_result(method_name, success, started_at, transport)
                }
                MaybeRpcMetricsLogger::NoOp => {}
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

    #[cfg(test)]
    mod tests {
        use crate::{context::RpcContext, test_client::TestClientBuilder, RpcServer};
        use jsonrpsee::core::Error;
        use jsonrpsee::types::error::{CallError, METHOD_NOT_FOUND_CODE};
        use serde_json::json;

        #[tokio::test]
        async fn invalid_method_name_without_underscore_doesnt_crash_the_server() {
            let context = RpcContext::for_tests();
            let (_server_handle, address) = RpcServer::new("127.0.0.1:0".parse().unwrap(), context)
                .with_logger(crate::metrics::logger::RpcMetricsLogger)
                .run()
                .await
                .unwrap();

            let client = TestClientBuilder::default()
                .address(address)
                .build()
                .unwrap();

            let error = client
                .request::<serde_json::Value>("invalidmethodnamewithoutunderscore", json!([]))
                .await
                .unwrap_err();

            assert!(
                matches!(error, Error::Call(CallError::Custom(e)) if e.code() == METHOD_NOT_FOUND_CODE)
            );
        }
    }
}
