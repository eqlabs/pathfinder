//! StarkNet node JSON-RPC related modules.
mod error;
pub mod gas_price;
pub mod serde;
#[cfg(test)]
pub mod test_client;
#[cfg(test)]
pub mod test_setup;
#[cfg(test)]
pub mod tests;
pub mod v01;
pub mod v02;

use crate::monitoring::metrics::middleware::{MaybeRpcMetricsMiddleware, RpcMetricsMiddleware};
use jsonrpsee::{
    core::server::rpc_module::Methods,
    http_server::{HttpServerBuilder, HttpServerHandle, RpcModule},
};

use std::{net::SocketAddr, result::Result};
use v01::api::RpcApi;

pub struct RpcServer {
    addr: SocketAddr,
    api: RpcApi,
    middleware: MaybeRpcMetricsMiddleware,
}

impl RpcServer {
    pub fn new(addr: SocketAddr, api: RpcApi) -> Self {
        Self {
            addr,
            api,
            middleware: MaybeRpcMetricsMiddleware::NoOp,
        }
    }

    pub fn with_middleware(self, middleware: RpcMetricsMiddleware) -> Self {
        Self {
            middleware: MaybeRpcMetricsMiddleware::Middleware(middleware),
            ..self
        }
    }

    /// Starts the HTTP-RPC server.
    pub async fn run(self) -> Result<(HttpServerHandle, SocketAddr), anyhow::Error> {
        let server = HttpServerBuilder::default()
            .set_middleware(self.middleware)
            .build(self.addr)
            .await
            .map_err(|e| match e {
                jsonrpsee::core::Error::Transport(_) => {
                    use std::error::Error;

                    if let Some(inner) = e.source().and_then(|inner| inner.downcast_ref::<std::io::Error>()) {
                        if let std::io::ErrorKind::AddrInUse = inner.kind() {
                            return anyhow::Error::new(e)
                                .context(format!("RPC address is already in use: {}.

Hint: This usually means you are already running another instance of pathfinder.
Hint: If this happens when upgrading, make sure to shut down the first one first.
Hint: If you are looking to run two instances of pathfinder, you must configure them with different http rpc addresses.", self.addr));
                        }
                    }

                    anyhow::Error::new(e)
                }
                _ => anyhow::Error::new(e),
            })?;
        let local_addr = server.local_addr()?;

        let context_v02 = (&self.api).into();

        let mut module_v01 = v01::RpcModuleWrapper::new(RpcModule::new(self.api));
        v01::register_all_methods(&mut module_v01)?;
        let module_v01: Methods = module_v01.into_inner().into();

        let mut module_v02 = RpcModule::new(context_v02);
        v02::register_all_methods(&mut module_v02)?;
        let module_v02 = module_v02.into();

        Ok(server
            .start_with_paths([
                (vec!["/", "/rpc/v0.1"], module_v01),
                (vec!["/rpc/v0.2"], module_v02),
            ])
            .map(|handle| (handle, local_addr))?)
    }
}
