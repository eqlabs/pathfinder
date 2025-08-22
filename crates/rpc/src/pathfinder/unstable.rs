//! This RPC API should **always** be considered unstable and for internal use
//! only. It's main purpose is to aid integration testing so expect it to change
//! anythime!

use crate::jsonrpc::{RpcRouter, RpcRouterBuilder};
use crate::method::consensus_info;

pub fn register_routes() -> RpcRouterBuilder {
    RpcRouter::builder(crate::RpcVersion::PathfinderV01)
        .register("pathfinder_consensusInfo", consensus_info::consensus_info)
}
