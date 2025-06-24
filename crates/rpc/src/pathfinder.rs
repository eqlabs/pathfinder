use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};

#[rustfmt::skip]
pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::PathfinderV01)
        .register("pathfinder_version",              || { pathfinder_version::VERSION })
}
