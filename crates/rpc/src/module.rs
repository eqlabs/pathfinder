use std::sync::Arc;

use jsonrpsee::core::server::rpc_module::Methods;

use crate::context::RpcContext;
use crate::error::RpcError;

/// A builder for registering a set of JSON-RPC methods which can be
/// hosted at a single endpoint.
pub struct Module(jsonrpsee::RpcModule<RpcContext>);

impl Module {
    pub fn new(context: RpcContext) -> Self {
        Self(jsonrpsee::RpcModule::new(context))
    }

    pub fn build(self) -> Methods {
        self.0.into()
    }

    /// Registers a JSON-RPC method with input parameters.
    ///
    /// An example signature for `method` is:
    /// ```ignore
    /// async fn method(context: RpcContext, input: Input) -> Result<Ouput, Error>
    /// ```
    pub fn register_method<Input, Output, Error, MethodFuture, Method>(
        mut self,
        method_name: &'static str,
        method: Method,
    ) -> anyhow::Result<Self>
    where
        Input: ::serde::de::DeserializeOwned + Send + Sync,
        Output: 'static + ::serde::Serialize + Send + Sync,
        Error: Into<RpcError>,
        MethodFuture: std::future::Future<Output = Result<Output, Error>> + Send,
        Method: (Fn(RpcContext, Input) -> MethodFuture) + Copy + Send + Sync + 'static,
    {
        use anyhow::Context;
        use jsonrpsee::types::Params;
        use tracing::Instrument;

        metrics::register_counter!("rpc_method_calls_total", "method" => method_name);

        let method_callback = move |params: Params<'static>, context: Arc<RpcContext>| {
            // why info here? it's the same used in warp tracing filter for example.
            let span = tracing::info_span!("rpc_method", name = method_name);
            async move {
                let input = params.parse::<Input>()?;
                method((*context).clone(), input).await.map_err(|err| {
                    let rpc_err: RpcError = err.into();
                    jsonrpsee::core::Error::from(rpc_err)
                })
            }
            .instrument(span)
        };

        self.0
            .register_async_method(method_name, method_callback)
            .with_context(|| format!("Registering {method_name}"))?;

        Ok(self)
    }

    /// Registers a JSON-RPC method without any input parameters.
    ///
    /// An example signature for `method` is:
    /// ```ignore
    /// async fn method(context: RpcContext) -> Result<Ouput, Error>
    /// ```
    pub fn register_method_with_no_input<Output, Error, MethodFuture, Method>(
        mut self,
        method_name: &'static str,
        method: Method,
    ) -> anyhow::Result<Self>
    where
        Output: 'static + ::serde::Serialize + Send + Sync,
        Error: Into<RpcError>,
        MethodFuture: std::future::Future<Output = Result<Output, Error>> + Send,
        Method: (Fn(RpcContext) -> MethodFuture) + Copy + Send + Sync + 'static,
    {
        use anyhow::Context;
        use tracing::Instrument;

        metrics::register_counter!("rpc_method_calls_total", "method" => method_name);

        let method_callback = move |_params, context: Arc<RpcContext>| {
            // why info here? it's the same used in warp tracing filter for example.
            let span = tracing::info_span!("rpc_method", name = method_name);
            async move {
                method((*context).clone()).await.map_err(|err| {
                    let rpc_err: RpcError = err.into();
                    jsonrpsee::core::Error::from(rpc_err)
                })
            }
            .instrument(span)
        };

        self.0
            .register_async_method(method_name, method_callback)
            .with_context(|| format!("Registering {method_name}"))?;

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::RpcContext;
    use crate::error::RpcError;
    use crate::test_client::TestClientBuilder;
    use jsonrpsee::http_server::HttpServerBuilder;
    use jsonrpsee::rpc_params;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    #[tokio::test]
    async fn without_input() {
        let ctx = RpcContext::for_tests();

        async fn say_hello(_: RpcContext) -> Result<String, RpcError> {
            Ok("hello".to_string())
        }

        let methods = super::Module::new(ctx)
            .register_method_with_no_input("say_hello", say_hello)
            .unwrap()
            .build();

        let server = HttpServerBuilder::default()
            .build(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let _jh = server.start(methods).unwrap();

        let client = TestClientBuilder::default()
            .request_timeout(std::time::Duration::from_secs(2))
            .address(addr)
            .build()
            .unwrap();

        let message = client.request::<String>("say_hello", None).await.unwrap();
        assert_eq!(message.as_str(), "hello");
    }

    #[tokio::test]
    async fn with_input() {
        use jsonrpsee::rpc_params;

        let ctx = RpcContext::for_tests();

        // Required because jsonrpsee api is a pita to use.
        #[derive(serde::Deserialize, serde::Serialize, Clone)]
        struct EchoInput {
            inner: String,
        }

        async fn echo(_: RpcContext, input: EchoInput) -> Result<String, RpcError> {
            Ok(input.inner)
        }

        let methods = super::Module::new(ctx)
            .register_method("echo", echo)
            .unwrap()
            .build();

        let server = HttpServerBuilder::default()
            .build(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();

        let _jh = server.start(methods).unwrap();

        let client = TestClientBuilder::default()
            .request_timeout(std::time::Duration::from_secs(2))
            .address(addr)
            .build()
            .unwrap();

        let input = "testing testing 123".to_string();

        let message = client
            .request::<String>("echo", rpc_params!(input.clone()))
            .await
            .unwrap();
        assert_eq!(message, input);
    }
}
