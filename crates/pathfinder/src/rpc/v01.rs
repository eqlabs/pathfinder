pub mod api;
pub mod types;

/// Helper wrapper for attaching spans to rpc method implementations
pub struct RpcModuleWrapper<Context>(jsonrpsee::RpcModule<Context>);

impl<Context: Send + Sync + 'static> RpcModuleWrapper<Context> {
    pub fn new(context: jsonrpsee::RpcModule<Context>) -> Self {
        Self(context)
    }

    /// This wrapper helper adds a tracing span around all rpc methods with name = method_name.
    ///
    /// It could do more, for example trace the outputs, durations.
    ///
    /// This is the only one method provided at the moment, because it's the only one used. If you
    /// need to use some other `register_*` method from [`jsonrpsee::RpcModule`], just add it to
    /// this wrapper.
    pub fn register_async_method<R, Fun, Fut>(
        &mut self,
        method_name: &'static str,
        callback: Fun,
    ) -> Result<
        jsonrpsee::core::server::rpc_module::MethodResourcesBuilder<'_>,
        jsonrpsee::core::Error,
    >
    where
        R: ::serde::Serialize + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<R, jsonrpsee::core::Error>> + Send,
        Fun: (Fn(jsonrpsee::types::Params<'static>, std::sync::Arc<Context>) -> Fut)
            + Copy
            + Send
            + Sync
            + 'static,
    {
        use tracing::Instrument;

        metrics::register_counter!("rpc_method_calls_total", "method" => method_name);

        self.0.register_async_method(method_name, move |p, c| {
            // why info here? it's the same used in warp tracing filter for example.
            let span = tracing::info_span!("rpc_method", name = method_name);
            callback(p, c).instrument(span)
        })
    }

    pub fn into_inner(self) -> jsonrpsee::RpcModule<Context> {
        self.0
    }
}
